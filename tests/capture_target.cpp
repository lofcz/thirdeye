
#include <windows.h>
#include <cstdio>
#include "marker.h"

static const wchar_t* kWindowClass = L"thirdeye_capture_target";
static const wchar_t* kReadyEvent  = L"thirdeye_target_ready";

const int kBoxSize = kMarkerBoxSize;
const int kBorder   = kMarkerBorder;

static void PaintMarker(HWND hwnd, HDC hdc, const RECT& rc) {

    HBRUSH white = CreateSolidBrush(RGB(0xFF, 0xFF, 0xFF));
    FillRect(hdc, &rc, white);
    DeleteObject(white);

    const int o = kBorder;
    RECT quads[4] = {
        { rc.left + o,            rc.top + o,            rc.left + o + kBoxSize,     rc.top + o + kBoxSize     },
        { rc.left + o + kBoxSize, rc.top + o,            rc.left + o + 2 * kBoxSize, rc.top + o + kBoxSize     },
        { rc.left + o,            rc.top + o + kBoxSize, rc.left + o + kBoxSize,     rc.top + o + 2 * kBoxSize },
        { rc.left + o + kBoxSize, rc.top + o + kBoxSize, rc.left + o + 2 * kBoxSize, rc.top + o + 2 * kBoxSize },
    };
    for (int i = 0; i < 4; i++) {
        HBRUSH brush = CreateSolidBrush(kMarkerQuad[i]);
        FillRect(hdc, &quads[i], brush);
        DeleteObject(brush);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            PaintMarker(hwnd, hdc, rc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = kWindowClass;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    if (!RegisterClassW(&wc)) {
        fprintf(stderr, "[target] RegisterClass failed: %lu\n", GetLastError());
        return 1;
    }

    RECT want = { 0, 0, 2 * kBorder + 2 * kBoxSize, 2 * kBorder + 2 * kBoxSize };
    AdjustWindowRect(&want, WS_OVERLAPPEDWINDOW, FALSE);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST, kWindowClass, L"thirdeye_capture_target",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        want.right - want.left, want.bottom - want.top,
        nullptr, nullptr, hInst, nullptr);
    if (!hwnd) {
        fprintf(stderr, "[target] CreateWindow failed: %lu\n", GetLastError());
        return 1;
    }

    ShowWindow(hwnd, SW_SHOW);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    UpdateWindow(hwnd);

    if (!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
        fprintf(stderr, "[target] SetWindowDisplayAffinity failed: %lu\n", GetLastError());

    }

    InvalidateRect(hwnd, nullptr, TRUE);
    UpdateWindow(hwnd);

    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, kReadyEvent);
    if (ready) {
        SetEvent(ready);
    }

    printf("[target] ready hwnd=%p\n", (void*)hwnd);
    fflush(stdout);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (ready) CloseHandle(ready);
    return 0;
}
