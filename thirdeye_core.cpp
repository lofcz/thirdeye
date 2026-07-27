#include "thirdeye_core.h"
#include "internal.h"
#include "lge_syscalls.h"
#include "dynresolve.h"
#include <gdiplus.h>
#include <iostream>
#include <sstream>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>

using namespace Gdiplus;

static std::mutex g_GdiPlusMutex;
static std::atomic g_ContextCount{0};
static ULONG_PTR g_GdiplusToken = 0;
static std::once_flag g_SyscallInitFlag;
static bool g_SyscallInitResult = false;

void SetLastErrorMsg(ThirdeyeContext* ctx, const char* msg) {
    if (ctx) {
        strncpy(ctx->lastError, msg, sizeof(ctx->lastError) - 1);
        ctx->lastError[sizeof(ctx->lastError) - 1] = '\0';
    }
}

HMODULE GetNtdllHandle() {
    static HMODULE hNtdll = nullptr;
    if (!hNtdll) {
        static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
        hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll).c_str());
    }
    return hNtdll;
}

DWORD GetSyscallNumber(const char* funcName) {
    HMODULE hNtdll = GetNtdllHandle();
    if (!hNtdll) return 0;

    BYTE* pBase = (BYTE*)hNtdll;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;
    BYTE* pEnd = pBase + pNt->OptionalHeader.SizeOfImage;

    BYTE* pFunc = (BYTE*)DynGetProcAddress(hNtdll, funcName);
    if (!pFunc) return 0;

    auto IsCleanStub = [](const BYTE* s) {
        return s[0] == 0x4C && s[1] == 0x8B && s[2] == 0xD1 && s[3] == 0xB8 &&
               s[6] == 0x00 && s[7] == 0x00;
    };
    auto ReadSsn = [](const BYTE* s) -> WORD {
        return (WORD)((s[5] << 8) | s[4]);
    };

    if (IsCleanStub(pFunc)) {
        return ReadSsn(pFunc);
    }

    const bool hookedAt0 = (pFunc[0] == 0xE9);
    const bool hookedAt3 = (pFunc[3] == 0xE9);
    if (!hookedAt0 && !hookedAt3) {
        return 0;
    }

    constexpr int STUB_SIZE = 32;  
    constexpr int MAX_SEARCH = 500;
    for (int idx = 1; idx <= MAX_SEARCH; idx++) {

        BYTE* down = pFunc + (idx * STUB_SIZE);
        if (down + 8 <= pEnd && IsCleanStub(down)) {
            return (DWORD)(ReadSsn(down) - idx);
        }

        BYTE* up = pFunc - (idx * STUB_SIZE);
        if (up >= pBase && up + 8 <= pEnd && IsCleanStub(up)) {
            return (DWORD)(ReadSsn(up) + idx);
        }
    }

    return 0;
}

bool InitializeSyscalls() {

    return LgeInitialize();
}

HANDLE NtOpenProcessDirect(DWORD pid, ACCESS_MASK desiredAccess) {
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = nullptr;

    NTSTATUS status = SyscallNtOpenProcess(&hProcess, desiredAccess, &oa, &cid);
    return NT_SUCCESS(status) ? hProcess : nullptr;
}

PVOID NtAllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect) {
    PVOID baseAddr = nullptr;
    SIZE_T regionSize = size;

    NTSTATUS status = SyscallNtAllocateVirtualMemory(
        hProcess, &baseAddr, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, protect
    );

    return NT_SUCCESS(status) ? baseAddr : nullptr;
}

bool NtWriteMemoryDirect(HANDLE hProcess, PVOID dest, PVOID src, SIZE_T size) {
    SIZE_T written = 0;
    NTSTATUS status = SyscallNtWriteVirtualMemory(hProcess, dest, src, size, &written);
    return NT_SUCCESS(status) && written == size;
}

void NtFreeMemoryDirect(HANDLE hProcess, PVOID addr) {
    PVOID baseAddr = addr;
    SIZE_T regionSize = 0;
    SyscallNtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, MEM_RELEASE);
}

HANDLE NtCreateThreadDirect(HANDLE hProcess, PVOID startAddr, PVOID param) {
    HANDLE hThread = nullptr;

    NTSTATUS status = SyscallNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        startAddr,
        param,
        0,
        0,
        0,
        0,
        nullptr
    );

    return NT_SUCCESS(status) ? hThread : nullptr;
}

void NtCloseDirect(HANDLE handle) {
    if (handle && handle != INVALID_HANDLE_VALUE) {
        SyscallNtClose(handle);
    }
}

bool NtProtectMemoryDirect(HANDLE hProcess, PVOID addr, SIZE_T size, ULONG newProtect, PULONG oldProtect) {
    PVOID baseAddr = addr;
    SIZE_T regionSize = size;
    NTSTATUS status = SyscallNtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, newProtect, oldProtect);
    return NT_SUCCESS(status);
}

DWORD NtWaitDirect(HANDLE handle, DWORD milliseconds) {
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)milliseconds * 10000);

    NTSTATUS status = SyscallNtWaitForSingleObject(handle, FALSE, &timeout);

    if (status == 0x00000000) return WAIT_OBJECT_0;
    if (status == 0x00000102) return WAIT_TIMEOUT;
    if (status == 0x00000080) return WAIT_ABANDONED;
    return WAIT_FAILED;
}

#ifndef __GNUC__
#pragma runtime_checks( "", off )
#pragma optimize( "", off )
#pragma check_stack( off )
#endif

extern "C" SEC_REMOTE FUNC_ATTRS
DWORD __stdcall RemoteThreadProc(LPVOID lpParameter) {
    INJECTION_DATA* pData = (INJECTION_DATA*)lpParameter;

#if defined(_M_X64) || defined(__x86_64__)
    PPEB_FULL pPeb = (PPEB_FULL)__readgsqword(0x60);
#else
    PPEB_FULL pPeb = (PPEB_FULL)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA_FULL pLdr = pPeb->Ldr;
    PRTL_CRITICAL_SECTION pLock = pPeb->FastPebLock;

    HMODULE hNtdll = nullptr;
    {
        PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
        PLIST_ENTRY pListEntry = pListHead->Flink;
        int count = 0;
        while (pListEntry != pListHead && count < 3) {
            PLDR_DATA_TABLE_ENTRY_FULL pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
            if (pEntry->BaseDllName.Buffer && pEntry->DllBase) {
                const WCHAR* ws = pEntry->BaseDllName.Buffer;
                const char* s = pData->ntdllName;
                bool match = true;
                while (*ws && *s) {
                    char c1 = (char)*ws, c2 = *s;
                    if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                    if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                    if (c1 != c2) { match = false; break; }
                    ws++; s++;
                }
                if (match && *ws == 0 && *s == 0) {
                    hNtdll = (HMODULE)pEntry->DllBase;
                    break;
                }
            }
            pListEntry = pListEntry->Flink;
            count++;
        }
    }
    if (!hNtdll) return 1;

    pRtlEnterCriticalSection fnEnterCS = nullptr;
    pRtlLeaveCriticalSection fnLeaveCS = nullptr;
    {
        BYTE* pBase = (BYTE*)hNtdll;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 1;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return 1;
        DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) return 1;
        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportRva);
        DWORD* pNames = (DWORD*)(pBase + pExport->AddressOfNames);
        WORD* pOrdinals = (WORD*)(pBase + pExport->AddressOfNameOrdinals);
        DWORD* pFunctions = (DWORD*)(pBase + pExport->AddressOfFunctions);

        for (DWORD i = 0; i < pExport->NumberOfNames && (!fnEnterCS || !fnLeaveCS); i++) {
            const char* name = (const char*)(pBase + pNames[i]);
            const char* targets[2] = { pData->enterCritSecName, pData->leaveCritSecName };
            FARPROC* results[2] = { (FARPROC*)&fnEnterCS, (FARPROC*)&fnLeaveCS };
            for (int t = 0; t < 2; t++) {
                if (*results[t]) continue;
                const char* s1 = name;
                const char* s2 = targets[t];
                bool match = true;
                while (*s1 && *s2) {
                    char c1 = *s1, c2 = *s2;
                    if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                    if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                    if (c1 != c2) { match = false; break; }
                    s1++; s2++;
                }
                if (match && *s1 == 0 && *s2 == 0) {
                    *results[t] = (FARPROC)(pBase + pFunctions[pOrdinals[i]]);
                }
            }
        }
    }
    if (!fnEnterCS || !fnLeaveCS) return 1;

    HMODULE hKernel32 = nullptr;
    fnEnterCS(pLock);
    {
        PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;
        PLIST_ENTRY pListEntry = pListHead->Flink;
        while (pListEntry != pListHead) {
            PLDR_DATA_TABLE_ENTRY_FULL pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
            if (pEntry->BaseDllName.Buffer && pEntry->DllBase) {
                const WCHAR* ws = pEntry->BaseDllName.Buffer;
                const char* s = pData->kernel32Name;
                bool match = true;
                while (*ws && *s) {
                    char c1 = (char)*ws, c2 = *s;
                    if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                    if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                    if (c1 != c2) { match = false; break; }
                    ws++; s++;
                }
                if (match && *ws == 0 && *s == 0) {
                    hKernel32 = (HMODULE)pEntry->DllBase;
                    break;
                }
            }
            pListEntry = pListEntry->Flink;
        }
    }
    fnLeaveCS(pLock);
    if (!hKernel32) return 1;

    pGetModuleHandleA fnGetModuleHandleA = nullptr;
    pGetProcAddress fnGetProcAddress = nullptr;
    pWaitForSingleObject fnWaitForSingleObject = nullptr;
    pReleaseSemaphore fnReleaseSemaphore = nullptr;
    {
        BYTE* pBase = (BYTE*)hKernel32;
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 1;

        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return 1;

        DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) return 1;

        PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportRva);
        DWORD* pNames = (DWORD*)(pBase + pExport->AddressOfNames);
        WORD* pOrdinals = (WORD*)(pBase + pExport->AddressOfNameOrdinals);
        DWORD* pFunctions = (DWORD*)(pBase + pExport->AddressOfFunctions);

        const char* targets[4] = { pData->getModuleFuncName, pData->getProcFuncName, pData->waitFuncName, pData->releaseFuncName };
        FARPROC* results[4] = { (FARPROC*)&fnGetModuleHandleA, (FARPROC*)&fnGetProcAddress, (FARPROC*)&fnWaitForSingleObject, (FARPROC*)&fnReleaseSemaphore };

        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            const char* name = (const char*)(pBase + pNames[i]);

            for (int t = 0; t < 4; t++) {
                if (*results[t]) continue;
                const char* s1 = name;
                const char* s2 = targets[t];
                bool match = true;
                while (*s1 && *s2) {
                    char c1 = *s1, c2 = *s2;
                    if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                    if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
                    if (c1 != c2) { match = false; break; }
                    s1++; s2++;
                }
                if (match && *s1 == 0 && *s2 == 0) {
                    *results[t] = (FARPROC)(pBase + pFunctions[pOrdinals[i]]);
                }
            }
        }
    }
    if (!fnGetModuleHandleA || !fnGetProcAddress || !fnWaitForSingleObject || !fnReleaseSemaphore) return 1;

    typedef DWORD(NTAPI* pSetWDA)(HWND, DWORD);
    typedef DWORD(NTAPI* pGetWDA)(HWND, DWORD*);

    pSetWDA fnSetWDA = nullptr;
    pGetWDA fnGetWDA = nullptr;

    HMODULE hLib = fnGetModuleHandleA(pData->libName);
    if (hLib) {
        fnSetWDA = (pSetWDA)fnGetProcAddress(hLib, pData->setFuncName);
        fnGetWDA = (pGetWDA)fnGetProcAddress(hLib, pData->getFuncName);
    }

    if (!fnSetWDA || !fnGetWDA) return 1;

    for (DWORD i = 0; i < pData->count; i++) {
        pData->originalAffinities[i] = 0;

        if (!pData->hwnds[i]) continue;

        DWORD currentAffinity = 0;
        if (!fnGetWDA(pData->hwnds[i], &currentAffinity)) continue;
        if (currentAffinity == 0) continue;

        if (!fnSetWDA(pData->hwnds[i], 0)) continue;

        DWORD verifyAffinity = 0;
        if (!fnGetWDA(pData->hwnds[i], &verifyAffinity)) continue;
        if (verifyAffinity != 0) continue;

        pData->originalAffinities[i] = currentAffinity;
    }

    if (pData->hReadySemaphore) {
        fnReleaseSemaphore(pData->hReadySemaphore, 1, nullptr);
    }

    fnWaitForSingleObject(pData->hGlobalTriggerEvent, 10000);

    for (DWORD i = 0; i < pData->count; i++) {
        if (pData->originalAffinities[i] != 0) {
            fnSetWDA(pData->hwnds[i], pData->originalAffinities[i]);
        }
    }

    return 0;
}

#ifndef __GNUC__
#pragma runtime_checks( "", restore )
#pragma optimize( "", on )
#pragma check_stack( on )
#endif

size_t GetRemoteSectionSize() {

#if defined(_M_X64) || defined(__x86_64__)
    PPEB_FULL pPeb = (PPEB_FULL)__readgsqword(0x60);
#else
    PPEB_FULL pPeb = (PPEB_FULL)__readfsdword(0x30);
#endif
    HMODULE hMod = pPeb ? (HMODULE)pPeb->ImageBaseAddress : nullptr;
    if (!hMod) {
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)pSectionHeader[i].Name, REMOTE_SECTION_NAME, 8) == 0) {
            size_t size = pSectionHeader[i].Misc.VirtualSize;
            return (size + 4095) & ~4095;
        }
    }
    return 0;
}

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0, size = 0;
    GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    ImageCodecInfo* pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
    if (!pImageCodecInfo) return -1;
    GetImageEncoders(num, size, pImageCodecInfo);
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    free(pImageCodecInfo);
    return -1;
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    auto* processWindows = (std::map<DWORD, std::vector<HWND>>*)lParam;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) {
        if ((*processWindows)[pid].size() < MAX_HWNDS_PER_PID) {
            (*processWindows)[pid].push_back(hwnd);
        }
    }
    return TRUE;
}

static bool IsProcessBlacklisted(DWORD pid) {
    return pid <= 4;
}

static void CleanupInjections(std::vector<RemoteContext>& injections) {
    if (injections.empty()) return;

    for (const auto& ctx : injections) {
        if (ctx.hThread) {
            if (NtWaitDirect(ctx.hThread, 200) == WAIT_OBJECT_0) {
                if (ctx.pRemoteCode) NtFreeMemoryDirect(ctx.hProcess, ctx.pRemoteCode);
                if (ctx.pRemoteData) NtFreeMemoryDirect(ctx.hProcess, ctx.pRemoteData);
            }
            NtCloseDirect(ctx.hThread);
        }

        if (ctx.hProcess) NtCloseDirect(ctx.hProcess);
    }
    injections.clear();
}

static bool BypassDisplayProtection(ThirdeyeContext* ctx, HANDLE hGlobalTrigger, std::vector<RemoteContext>& activeInjections) {
    std::map<DWORD, std::vector<HWND>> processWindows;
    EnumWindows(EnumWindowsProc, (LPARAM)&processWindows);
    size_t skippedBlacklisted = 0;
    size_t openFailed = 0;
    size_t opened = 0;
    size_t duplicateFailed = 0;
    size_t allocationFailed = 0;
    size_t writeFailed = 0;
    size_t threadFailed = 0;

    if (!hGlobalTrigger) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Invalid trigger event")));
        return false;
    }

    HandleGuard hReadySemaphore(CreateSemaphoreA(nullptr, 0, 1000, nullptr));
    if (!hReadySemaphore) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Failed to create ready semaphore")));
        return false;
    }

    size_t sectionSize = GetRemoteSectionSize();
    if (sectionSize == 0) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Injection code section not found")));
        return false;
    }

    for (auto const& [pid, hwnds] : processWindows) {
        if (IsProcessBlacklisted(pid)) {
            skippedBlacklisted++;
            continue;
        }

        HANDLE hProcess = NtOpenProcessDirect(pid, PROCESS_ALL_ACCESS);
        if (!hProcess) {
            openFailed++;
            continue;
        }
        opened++;

        INJECTION_DATA data = { 0 };
        data.count = hwnds.size() < MAX_HWNDS_PER_PID ? (DWORD)hwnds.size() : MAX_HWNDS_PER_PID;
        for (size_t i = 0; i < data.count; i++) data.hwnds[i] = hwnds[i];

        static constexpr auto obfKernel32 = MAKE_OBF("kernel32.dll");
        static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
        static constexpr auto obfGetModule = MAKE_OBF("GetModuleHandleA");
        static constexpr auto obfGetProc = MAKE_OBF("GetProcAddress");
        static constexpr auto obfWait = MAKE_OBF("WaitForSingleObject");
        static constexpr auto obfRelease = MAKE_OBF("ReleaseSemaphore");
        static constexpr auto obfEnterCS = MAKE_OBF("RtlEnterCriticalSection");
        static constexpr auto obfLeaveCS = MAKE_OBF("RtlLeaveCriticalSection");

        if (!SafeCopyString(data.kernel32Name, DECR_STR(obfKernel32)) ||
            !SafeCopyString(data.ntdllName, DECR_STR(obfNtdll)) ||
            !SafeCopyString(data.getModuleFuncName, DECR_STR(obfGetModule)) ||
            !SafeCopyString(data.getProcFuncName, DECR_STR(obfGetProc)) ||
            !SafeCopyString(data.waitFuncName, DECR_STR(obfWait)) ||
            !SafeCopyString(data.releaseFuncName, DECR_STR(obfRelease)) ||
            !SafeCopyString(data.enterCritSecName, DECR_STR(obfEnterCS)) ||
            !SafeCopyString(data.leaveCritSecName, DECR_STR(obfLeaveCS))) {
            NtCloseDirect(hProcess);
            writeFailed++;
            continue;
        }

        if (!DuplicateHandle(GetCurrentProcess(), hGlobalTrigger, hProcess, &data.hGlobalTriggerEvent,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
            NtCloseDirect(hProcess);
            duplicateFailed++;
            continue;
        }

        if (!DuplicateHandle(GetCurrentProcess(), hReadySemaphore.get(), hProcess, &data.hReadySemaphore,
            SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, FALSE, 0)) {
            NtCloseDirect(hProcess);
            duplicateFailed++;
            continue;
        }

        static constexpr auto obfWin32u = MAKE_OBF("win32u.dll");
        static constexpr auto obfSetWDA = MAKE_OBF("NtUserSetWindowDisplayAffinity");
        static constexpr auto obfGetWDA = MAKE_OBF("NtUserGetWindowDisplayAffinity");

        if (!SafeCopyString(data.libName, DECR_STR(obfWin32u)) ||
            !SafeCopyString(data.setFuncName, DECR_STR(obfSetWDA)) ||
            !SafeCopyString(data.getFuncName, DECR_STR(obfGetWDA))) {
            NtCloseDirect(hProcess);
            writeFailed++;
            continue;
        }

        LPVOID pRemoteData = NtAllocateMemoryDirect(hProcess, sizeof(INJECTION_DATA), PAGE_READWRITE);
        if (!pRemoteData) {
            NtCloseDirect(hProcess);
            allocationFailed++;
            continue;
        }

        LPVOID pRemoteCode = NtAllocateMemoryDirect(hProcess, sectionSize, PAGE_READWRITE);
        if (!pRemoteCode) {
            NtFreeMemoryDirect(hProcess, pRemoteData);
            NtCloseDirect(hProcess);
            allocationFailed++;
            continue;
        }

        bool b1 = NtWriteMemoryDirect(hProcess, pRemoteData, &data, sizeof(INJECTION_DATA));
        bool b2 = NtWriteMemoryDirect(hProcess, pRemoteCode, (PVOID)RemoteThreadProc, sectionSize);

        ULONG oldProtect = 0;
        bool b3 = NtProtectMemoryDirect(hProcess, pRemoteCode, sectionSize, PAGE_EXECUTE_READ, &oldProtect);

        if (!b1 || !b2 || !b3) {
            NtFreeMemoryDirect(hProcess, pRemoteData);
            NtFreeMemoryDirect(hProcess, pRemoteCode);
            NtCloseDirect(hProcess);
            writeFailed++;
            continue;
        }

        HANDLE hThread = NtCreateThreadDirect(hProcess, pRemoteCode, pRemoteData);
        if (!hThread) {
            NtFreeMemoryDirect(hProcess, pRemoteData);
            NtFreeMemoryDirect(hProcess, pRemoteCode);
            NtCloseDirect(hProcess);
            threadFailed++;
            continue;
        }

        activeInjections.push_back({ hProcess, hThread, pRemoteData, pRemoteCode, pid });
    }

    if (!activeInjections.empty()) {
        for (size_t i = 0; i < activeInjections.size(); i++) {
            WaitForSingleObject(hReadySemaphore.get(), 1000);
        }
    }

#if defined(_DEBUG) || defined(THIRDEYE_DEBUG)
    std::ostringstream msg;
    msg << "bypass_diag processes=" << processWindows.size()
        << " skipped_blacklisted=" << skippedBlacklisted
        << " opened=" << opened
        << " injections=" << activeInjections.size()
        << " open_failed=" << openFailed
        << " duplicate_failed=" << duplicateFailed
        << " allocation_failed=" << allocationFailed
        << " write_failed=" << writeFailed
        << " thread_failed=" << threadFailed
        << " section_size=" << sectionSize;
    SetLastErrorMsg(ctx, msg.str().c_str());
#endif

    return true;
}

static const WCHAR* GetMimeType(ThirdeyeFormat format) {
    switch (format) {
        case THIRDEYE_FORMAT_PNG: return L"image/png";
        case THIRDEYE_FORMAT_BMP: return L"image/bmp";
        case THIRDEYE_FORMAT_JPEG:
        default: return L"image/jpeg";
    }
}

static ThirdeyeResult CaptureScreenToStream(ThirdeyeContext* ctx, IStream* stream, const ThirdeyeOptions* opts) {
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMemDC = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, w, h);
    SelectObject(hdcMemDC, hbm);

    BitBlt(hdcMemDC, 0, 0, w, h, hdcScreen, x, y, SRCCOPY);

    Bitmap bitmap(hbm, nullptr);

    CLSID clsid;
    const WCHAR* mimeType = GetMimeType(opts ? opts->format : THIRDEYE_FORMAT_JPEG);
    if (GetEncoderClsid(mimeType, &clsid) == -1) {
        DeleteObject(hbm);
        DeleteDC(hdcMemDC);
        ReleaseDC(nullptr, hdcScreen);
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Image encoder not found")));
        return THIRDEYE_ERROR_ENCODER_NOT_FOUND;
    }

    EncoderParameters encoderParams;
    ULONG quality = opts ? (ULONG)opts->quality : 90;

    if (opts && opts->format == THIRDEYE_FORMAT_JPEG) {
        encoderParams.Count = 1;
        encoderParams.Parameter[0].Guid = EncoderQuality;
        encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
        encoderParams.Parameter[0].NumberOfValues = 1;
        encoderParams.Parameter[0].Value = &quality;
        bitmap.Save(stream, &clsid, &encoderParams);
    } else {
        bitmap.Save(stream, &clsid, nullptr);
    }

    DeleteObject(hbm);
    DeleteDC(hdcMemDC);
    ReleaseDC(nullptr, hdcScreen);

    return THIRDEYE_OK;
}

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CreateContext(ThirdeyeContext** ppContext) {
    if (!ppContext) return THIRDEYE_ERROR_INVALID_PARAM;
    *ppContext = nullptr;

    std::call_once(g_SyscallInitFlag, []() {
        g_SyscallInitResult = InitializeSyscalls();
    });

    if (!g_SyscallInitResult) {
        return THIRDEYE_ERROR_SYSCALL_INIT_FAILED;
    }

    {
        std::lock_guard lock(g_GdiPlusMutex);
        if (g_ContextCount == 0) {
            GdiplusStartupInput gdiplusStartupInput;
            if (GdiplusStartup(&g_GdiplusToken, &gdiplusStartupInput, nullptr) != Ok) {
                return THIRDEYE_ERROR_GDIPLUS_INIT_FAILED;
            }
        }
        g_ContextCount++;
    }

    ThirdeyeContext* ctx = new ThirdeyeContext();
    memset(ctx->lastError, 0, sizeof(ctx->lastError));
    *ppContext = ctx;
    return THIRDEYE_OK;
}

THIRDEYE_API void THIRDEYE_CALL Thirdeye_DestroyContext(ThirdeyeContext* context) {
    if (!context) return;

    {
        std::lock_guard lock(g_GdiPlusMutex);
        g_ContextCount--;
        if (g_ContextCount <= 0) {
            g_ContextCount = 0;
            if (g_GdiplusToken) {
                GdiplusShutdown(g_GdiplusToken);
                g_GdiplusToken = 0;
            }
        }
    }

    delete context;
}

THIRDEYE_API void THIRDEYE_CALL Thirdeye_GetDefaultOptions(ThirdeyeOptions* options) {
    if (!options) return;
    options->format = THIRDEYE_FORMAT_JPEG;
    options->quality = 90;
    options->bypassProtection = 1;
}

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CaptureToFile(
    ThirdeyeContext* context,
    const wchar_t* filePath,
    const ThirdeyeOptions* options
) {
    if (!context) return THIRDEYE_ERROR_NOT_INITIALIZED;

    if (!filePath) {
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Invalid file path")));
        return THIRDEYE_ERROR_INVALID_PARAM;
    }

    ThirdeyeOptions opts;
    if (options) {
        opts = *options;
    } else {
        Thirdeye_GetDefaultOptions(&opts);
    }

    HandleGuard hGlobalTrigger;
    std::vector<RemoteContext> injections;
    if (opts.bypassProtection) {
        hGlobalTrigger = HandleGuard(CreateEventA(nullptr, TRUE, FALSE, nullptr));
        if (hGlobalTrigger) {
            BypassDisplayProtection(context, hGlobalTrigger.get(), injections);
        }
    }

    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMemDC = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, w, h);
    SelectObject(hdcMemDC, hbm);

    BitBlt(hdcMemDC, 0, 0, w, h, hdcScreen, x, y, SRCCOPY);

    if (opts.bypassProtection && hGlobalTrigger) {
        SetEvent(hGlobalTrigger.get());
        std::thread([injections = std::move(injections)]() mutable {
            CleanupInjections(injections);
        }).detach();
    }

    Bitmap bitmap(hbm, nullptr);

    CLSID clsid;
    const WCHAR* mimeType = GetMimeType(opts.format);
    if (GetEncoderClsid(mimeType, &clsid) == -1) {
        DeleteObject(hbm);
        DeleteDC(hdcMemDC);
        ReleaseDC(nullptr, hdcScreen);
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Image encoder not found")));
        return THIRDEYE_ERROR_ENCODER_NOT_FOUND;
    }

    Status saveStatus;
    if (opts.format == THIRDEYE_FORMAT_JPEG) {
        EncoderParameters encoderParams;
        ULONG quality = (ULONG)opts.quality;
        encoderParams.Count = 1;
        encoderParams.Parameter[0].Guid = EncoderQuality;
        encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
        encoderParams.Parameter[0].NumberOfValues = 1;
        encoderParams.Parameter[0].Value = &quality;
        saveStatus = bitmap.Save(filePath, &clsid, &encoderParams);
    } else {
        saveStatus = bitmap.Save(filePath, &clsid, nullptr);
    }

    DeleteObject(hbm);
    DeleteDC(hdcMemDC);
    ReleaseDC(nullptr, hdcScreen);

    if (saveStatus != Ok) {
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to save image")));
        return THIRDEYE_ERROR_SAVE_FAILED;
    }

    return THIRDEYE_OK;
}

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CaptureToBuffer(
    ThirdeyeContext* context,
    uint8_t** buffer,
    uint32_t* size,
    const ThirdeyeOptions* options
) {
    if (!context) return THIRDEYE_ERROR_NOT_INITIALIZED;

    if (!buffer || !size) {
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Invalid parameters")));
        return THIRDEYE_ERROR_INVALID_PARAM;
    }

    *buffer = nullptr;
    *size = 0;

    ThirdeyeOptions opts;
    if (options) {
        opts = *options;
    } else {
        Thirdeye_GetDefaultOptions(&opts);
    }

    HandleGuard hGlobalTrigger;
    std::vector<RemoteContext> injections;
    if (opts.bypassProtection) {
        hGlobalTrigger = HandleGuard(CreateEventA(nullptr, TRUE, FALSE, nullptr));
        if (hGlobalTrigger) {
            BypassDisplayProtection(context, hGlobalTrigger.get(), injections);
        }
    }

    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK) {
        if (opts.bypassProtection && hGlobalTrigger) {
            SetEvent(hGlobalTrigger.get());
            std::thread([injections = std::move(injections)]() mutable {
                CleanupInjections(injections);
            }).detach();
        }
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to create memory stream")));
        return THIRDEYE_ERROR_ALLOCATION_FAILED;
    }

    ThirdeyeResult result = CaptureScreenToStream(context, stream, &opts);

    if (opts.bypassProtection && hGlobalTrigger) {
        SetEvent(hGlobalTrigger.get());
        std::thread([injections = std::move(injections)]() mutable {
            CleanupInjections(injections);
        }).detach();
    }

    if (result != THIRDEYE_OK) {
        stream->Release();
        return result;
    }

    STATSTG stat;
    if (stream->Stat(&stat, STATFLAG_NONAME) != S_OK) {
        stream->Release();
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to get stream size")));
        return THIRDEYE_ERROR_ALLOCATION_FAILED;
    }

    uint32_t dataSize = (uint32_t)stat.cbSize.QuadPart;

    uint8_t* outBuffer = (uint8_t*)malloc(dataSize);
    if (!outBuffer) {
        stream->Release();
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to allocate output buffer")));
        return THIRDEYE_ERROR_ALLOCATION_FAILED;
    }

    LARGE_INTEGER zero = {0};
    stream->Seek(zero, STREAM_SEEK_SET, nullptr);
    ULONG bytesRead = 0;
    stream->Read(outBuffer, dataSize, &bytesRead);
    stream->Release();

    *buffer = outBuffer;
    *size = dataSize;

    return THIRDEYE_OK;
}

THIRDEYE_API void THIRDEYE_CALL Thirdeye_FreeBuffer(uint8_t* buffer) {
    if (buffer) {
        free(buffer);
    }
}

THIRDEYE_API const char* THIRDEYE_CALL Thirdeye_GetLastError(ThirdeyeContext* context) {
    if (context) {
        return context->lastError;
    }
    return "";
}

THIRDEYE_API const char* THIRDEYE_CALL Thirdeye_GetVersion(void) {
    return "1.0.0";
}
