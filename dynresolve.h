
#ifndef THIRDEYE_DYNRESOLVE_H
#define THIRDEYE_DYNRESOLVE_H

#include <windows.h>

HMODULE DynGetModuleHandle(const char* moduleName);

FARPROC DynGetProcAddress(HMODULE moduleBase, const char* funcName);

#endif
