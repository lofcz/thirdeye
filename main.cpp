#include <windows.h>
#include <gdiplus.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <map>

#pragma comment (lib,"Gdiplus.lib")
#pragma comment (lib, "User32.lib")

using namespace Gdiplus;

typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef DWORD(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* pSetEvent)(HANDLE);

#define MAX_HWNDS_PER_PID 256

struct INJECTION_DATA {
    DWORD count;
    HWND hwnds[MAX_HWNDS_PER_PID];
    DWORD originalAffinities[MAX_HWNDS_PER_PID];

    pGetModuleHandleA fnGetModuleHandleA;
    pGetProcAddress   fnGetProcAddress;
    pWaitForSingleObject fnWaitForSingleObject;

    HANDLE hGlobalTriggerEvent;

    char libName[16];
    char setFuncName[32];
    char getFuncName[32];
};

extern "C" __attribute__((optimize("O0")))
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

    if (!foundProtectedWindow) {
        return 0;
    }

    pData->fnWaitForSingleObject(pData->hGlobalTriggerEvent, 5000);

    for (DWORD i = 0; i < pData->count; i++) {
        if (pData->hwnds[i]) {
            if (pData->originalAffinities[i] != 0) {
                fnSetWDA(pData->hwnds[i], pData->originalAffinities[i]);
            }
        }
    }

    return 0;
}

extern "C" void __stdcall RemoteThreadProcEnd() {}

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

    HANDLE hGlobalEvent = CreateEventA(nullptr, TRUE, FALSE, "Global\\ThirdEye_Trigger");
    ResetEvent(hGlobalEvent);

    std::vector<HANDLE> openProcesses;

    for (auto const& [pid, hwnds] : g_ProcessWindows) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) continue;

        INJECTION_DATA data = { 0 };
        data.count = (DWORD)hwnds.size();
        for (size_t i = 0; i < data.count; i++) data.hwnds[i] = hwnds[i];

        data.fnGetModuleHandleA = GetModuleHandleA;
        data.fnGetProcAddress = GetProcAddress;
        data.fnWaitForSingleObject = WaitForSingleObject;

        HANDLE hTargetEvent;
        DuplicateHandle(GetCurrentProcess(), hGlobalEvent, hProcess, &hTargetEvent, 0, FALSE, DUPLICATE_SAME_ACCESS);
        data.hGlobalTriggerEvent = hTargetEvent;

        strcpy(data.libName, "win32u.dll");
        strcpy(data.setFuncName, "NtUserSetWindowDisplayAffinity");
        strcpy(data.getFuncName, "NtUserGetWindowDisplayAffinity");

        uintptr_t startAddr = (uintptr_t)&RemoteThreadProc;
        uintptr_t endAddr = (uintptr_t)&RemoteThreadProcEnd;
        size_t funcSize = (endAddr > startAddr) ? (endAddr - startAddr) : 2048;

        LPVOID pRemoteData = VirtualAllocEx(hProcess, nullptr, sizeof(INJECTION_DATA), MEM_COMMIT, PAGE_READWRITE);
        LPVOID pRemoteCode = VirtualAllocEx(hProcess, nullptr, funcSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (pRemoteData && pRemoteCode) {
            WriteProcessMemory(hProcess, pRemoteData, &data, sizeof(INJECTION_DATA), nullptr);
            WriteProcessMemory(hProcess, pRemoteCode, (LPCVOID)RemoteThreadProc, funcSize, nullptr);

            HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, pRemoteData, 0, nullptr);
            if (hThread) CloseHandle(hThread);

            openProcesses.push_back(hProcess);
        } else {
            CloseHandle(hProcess);
        }
    }

    std::cout << "[*] Injected." << std::endl;
    Sleep(300);

    SaveScreenshot();
    SetEvent(hGlobalEvent);

    Sleep(100);

    for (HANDLE h : openProcesses) CloseHandle(h);
    CloseHandle(hGlobalEvent);

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