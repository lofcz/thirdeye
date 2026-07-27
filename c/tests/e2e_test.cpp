
#include <windows.h>
#include <gdiplus.h>
#include <cstdio>
#include <cstdint>

#include "../thirdeye_core.h"

using namespace Gdiplus;

#include "marker.h"

static const wchar_t* kReadyEvent  = L"thirdeye_target_ready";
static const wchar_t* kTargetTitle = L"thirdeye_capture_target";
static const int kWaitReadyMs = 10000;

static int g_failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  [ok] %s\n", msg); } \
    else { printf("  [FAIL] %s\n", msg); ++g_failures; } \
} while (0)

static HANDLE StartTarget(PROCESS_INFORMATION& pi) {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(path, L'\\');
    if (lastSlash) *lastSlash = L'\0';
    wcscat_s(path, L"\\capture_target.exe");

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    if (!CreateProcessW(path, nullptr, nullptr, nullptr, FALSE, 0,
                        nullptr, nullptr, &si, &pi)) {
        return nullptr;
    }

    HANDLE ready = OpenEventW(SYNCHRONIZE, FALSE, kReadyEvent);
    if (!ready) {

        Sleep(500);
        ready = OpenEventW(SYNCHRONIZE, FALSE, kReadyEvent);
    }
    if (ready) {

        WaitForSingleObject(ready, kWaitReadyMs);
    }

    Sleep(1000);
    return ready;
}

static int CountMarkerHits(const uint8_t* bgra, int width, int height, int stride, int tolerance, bool* foundOut) {
    bool found[4] = { false, false, false, false };
    for (int y = 0; y < height; y++) {
        const uint8_t* row = bgra + (size_t)y * stride;
        for (int x = 0; x < width; x++) {
            uint8_t b = row[x * 4 + 0];
            uint8_t g = row[x * 4 + 1];
            uint8_t r = row[x * 4 + 2];
            for (int i = 0; i < 4; i++) {
                if (found[i]) continue;
                uint8_t mr = GetRValue(kMarkerQuad[i]);
                uint8_t mg = GetGValue(kMarkerQuad[i]);
                uint8_t mb = GetBValue(kMarkerQuad[i]);
                if (abs(r - mr) <= tolerance && abs(g - mg) <= tolerance && abs(b - mb) <= tolerance) {
                    found[i] = true;
                }
            }
        }
    }
    int hits = 0;
    for (int i = 0; i < 4; i++) {
        if (found[i]) hits++;
        if (foundOut) foundOut[i] = found[i];
    }
    return hits;
}

static Bitmap* CaptureRawScreen() {
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    HDC hdcScreen = GetDC(nullptr);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, w, h);
    SelectObject(hdcMem, hbm);
    BitBlt(hdcMem, 0, 0, w, h, hdcScreen, x, y, SRCCOPY);

    Bitmap* bmp = new Bitmap(hbm, nullptr);
    DeleteObject(hbm);
    DeleteDC(hdcMem);
    ReleaseDC(nullptr, hdcScreen);
    return bmp;
}

static int ScanBitmapRegion(Bitmap* bmp, Rect region, int tolerance, bool* foundOut = nullptr) {
    if (!bmp || bmp->GetLastStatus() != Ok) return 0;
    int bw = (int)bmp->GetWidth();
    int bh = (int)bmp->GetHeight();

    if (region.X < 0) region.X = 0;
    if (region.Y < 0) region.Y = 0;
    if (region.X + region.Width > bw) region.Width = bw - region.X;
    if (region.Y + region.Height > bh) region.Height = bh - region.Y;
    if (region.Width <= 0 || region.Height <= 0) return 0;

    BitmapData data;
    if (bmp->LockBits(&region, ImageLockModeRead, PixelFormat32bppARGB, &data) != Ok) {
        return 0;
    }
    int hits = CountMarkerHits((const uint8_t*)data.Scan0, region.Width, region.Height, abs(data.Stride), tolerance, foundOut);
    bmp->UnlockBits(&data);
    return hits;
}

static int ScanBitmap(Bitmap* bmp, int tolerance, bool* foundOut = nullptr) {
    if (!bmp) return 0;
    return ScanBitmapRegion(bmp, Rect(0, 0, (int)bmp->GetWidth(), (int)bmp->GetHeight()), tolerance, foundOut);
}

static Bitmap* DecodeJpeg(const uint8_t* buf, uint32_t size) {
    IStream* stream = nullptr;
    if (CreateStreamOnHGlobal(nullptr, TRUE, &stream) != S_OK) return nullptr;
    ULONG written = 0;
    stream->Write(buf, size, &written);
    Bitmap* bmp = Bitmap::FromStream(stream);
    stream->Release();
    if (bmp && bmp->GetLastStatus() != Ok) {
        delete bmp;
        return nullptr;
    }
    return bmp;
}

int main() {
    printf("[*] thirdeye E2E: WDA_EXCLUDEFROMCAPTURE bypass\n");

    ULONG_PTR gdiToken;
    GdiplusStartupInput gdiInput;
    if (GdiplusStartup(&gdiToken, &gdiInput, nullptr) != Ok) {
        printf("[!] GdiplusStartup failed\n");
        return 2;
    }

    PROCESS_INFORMATION pi = {};
    HANDLE ready = StartTarget(pi);
    if (!pi.hProcess) {
        printf("[!] failed to launch capture_target.exe\n");
        GdiplusShutdown(gdiToken);
        return 2;
    }
    printf("[*] target launched (pid=%lu)\n", pi.dwProcessId);

    HWND targetHwnd = FindWindowW(nullptr, kTargetTitle);
    CHECK(targetHwnd != nullptr, "target window located");
    RECT wrect = {};
    bool haveRect = targetHwnd && GetWindowRect(targetHwnd, &wrect);

    printf("[*] phase 1: baseline raw capture (expect marker absent)\n");
    Bitmap* baseline = CaptureRawScreen();

    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    Rect region(
        haveRect ? (wrect.left - vx) : 0,
        haveRect ? (wrect.top - vy) : 0,
        haveRect ? (wrect.right - wrect.left) : (int)baseline->GetWidth(),
        haveRect ? (wrect.bottom - wrect.top) : (int)baseline->GetHeight());
    bool baselineFound[4] = { false, false, false, false };
    int baselineHits = ScanBitmapRegion(baseline, region, 4, baselineFound);
    delete baseline;
    CHECK(baselineHits == 0, "baseline: marker absent from raw capture (exclusion active)");
    if (baselineHits > 0) {
        printf("      -> %d/4 marker colors leaked into raw capture; exclusion not active, test vacuous\n", baselineHits);
        for (int i = 0; i < 4; i++) {
            if (baselineFound[i]) printf("         leaked: %s\n", kMarkerNames[i]);
        }
    }

    Sleep(3000);

    printf("[*] phase 2: thirdeye bypass capture (expect marker present)\n");
    ThirdeyeContext* ctx = nullptr;
    ThirdeyeResult cr = Thirdeye_CreateContext(&ctx);
    CHECK(cr == THIRDEYE_OK && ctx != nullptr, "Thirdeye_CreateContext");

    int bypassHits = 0;
    if (cr == THIRDEYE_OK && ctx) {
        ThirdeyeOptions opts;
        Thirdeye_GetDefaultOptions(&opts);
        opts.format = THIRDEYE_FORMAT_JPEG;
        opts.quality = 95;
        opts.bypassProtection = 1;

        uint8_t* buf = nullptr;
        uint32_t size = 0;
        ThirdeyeResult capRes = Thirdeye_CaptureToBuffer(ctx, &buf, &size, &opts);
        CHECK(capRes == THIRDEYE_OK && buf && size > 0, "Thirdeye_CaptureToBuffer(bypass=1)");
        if (capRes != THIRDEYE_OK) {
            printf("      -> capture error: %s\n", Thirdeye_GetLastError(ctx));
        }

        if (buf && size > 0) {
            Bitmap* bypass = DecodeJpeg(buf, size);

            bypassHits = ScanBitmapRegion(bypass, region, 24);
            delete bypass;
            CHECK(bypassHits == 4, "bypass: all 4 marker colors visible (exclusion bypassed)");
            if (bypassHits != 4) {
                printf("      -> only %d/4 marker colors found in bypass capture\n", bypassHits);
            }
            Thirdeye_FreeBuffer(buf);
        }
        Thirdeye_DestroyContext(ctx);
    }

    if (pi.hProcess) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    if (ready) CloseHandle(ready);
    GdiplusShutdown(gdiToken);

    printf("==========================================\n");
    if (g_failures == 0) {
        printf("[PASS] thirdeye bypassed WDA_EXCLUDEFROMCAPTURE\n");
        return 0;
    }
    printf("[FAIL] %d check(s) failed\n", g_failures);
    return 1;
}
