#include "thirdeye_core.h"
#include <windows.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

static std::wstring GenerateFilename() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << "screen_" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d_%H-%M-%S") << ".jpg";
    std::string fileNameStr = ss.str();
    return std::wstring(fileNameStr.begin(), fileNameStr.end());
}

static void Capture(ThirdeyeContext* ctx) {
    std::cout << "[*] Capturing..." << std::endl;

    std::wstring filename = GenerateFilename();
    
    ThirdeyeOptions opts;
    Thirdeye_GetDefaultOptions(&opts);
    opts.format = THIRDEYE_FORMAT_JPEG;
    opts.quality = 90;
    opts.bypassProtection = 1;

    ThirdeyeResult result = Thirdeye_CaptureToFile(ctx, filename.c_str(), &opts);

    if (result == THIRDEYE_OK) {
        std::wcout << L"[+] Saved: " << filename << std::endl;
    } else {
        std::cerr << "[!] Capture failed: " << Thirdeye_GetLastError(ctx) << std::endl;
    }
}

[[noreturn]] int main() {
    std::cout << "[*] ThirdEye v" << Thirdeye_GetVersion() << std::endl;

    ThirdeyeContext* ctx = nullptr;
    ThirdeyeResult initResult = Thirdeye_CreateContext(&ctx);
    if (initResult != THIRDEYE_OK) {
        std::cerr << "[!] Initialization failed with error code: " << initResult << std::endl;
        exit(1);
    }

    std::cout << "[*] Press 'S' to capture." << std::endl;
    std::cout << std::endl;

    while (true) {
        if (GetAsyncKeyState(0x53) & 0x8000) {  // 'S' key
            Capture(ctx);
            Sleep(1000);
        }
        Sleep(50);
    }
}
