
#ifndef THIRDEYE_DYNRESOLVE_H
#define THIRDEYE_DYNRESOLVE_H

#include <windows.h>

HMODULE DynGetModuleHandle(const char* moduleName);

FARPROC DynGetProcAddress(HMODULE moduleBase, const char* funcName);

// Loads a module without LoadLibrary: resolves ntdll!LdrLoadDll by PEB walk +
// export parsing, then invokes it with a name supplied as a wide string. The
// wide name must remain valid for the duration of the call. Returns the module
// base, or nullptr on failure.
HMODULE DynLoadLibrary(const WCHAR* moduleName);

#endif
