
#ifndef THIRDEYE_DYNRESOLVE_H
#define THIRDEYE_DYNRESOLVE_H

#include <windows.h>

HMODULE DynGetModuleHandle(const char* moduleName);
FARPROC DynGetProcAddress(HMODULE moduleBase, const char* funcName);
HMODULE DynLoadLibrary(const WCHAR* moduleName);
HMODULE DynLoadLibraryA(const char* moduleName);

// Typed convenience resolver shared across translation units.
template <typename T>
static inline T ResolveApiT(HMODULE hMod, const char* name) {
    return (T)DynGetProcAddress(hMod, name);
}

static inline void TeAsciiToWide(wchar_t* dst, size_t dstChars, const char* src) {
    if (!dst || !dstChars) return;
    size_t i = 0;
    if (src) {
        for (; src[i] && i + 1 < dstChars; ++i)
            dst[i] = (wchar_t)(unsigned char)src[i];
    }
    dst[i < dstChars ? i : dstChars - 1] = 0;
}

static inline HMODULE DynGetOrLoad(const char* moduleNameA) {
    if (!moduleNameA) return nullptr;
    HMODULE h = DynGetModuleHandle(moduleNameA);
    if (h) return h;
    return DynLoadLibraryA(moduleNameA);
}

#endif
