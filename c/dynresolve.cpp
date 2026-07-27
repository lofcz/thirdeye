#include "dynresolve.h"
#include "internal.h"

namespace {

inline char ToLowerAscii(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

bool NameEqualsNarrow(const WCHAR* wide, const char* narrow) {
    if (!wide || !narrow) return false;
    while (*wide && *narrow) {
        if (ToLowerAscii((char)*wide) != ToLowerAscii(*narrow)) return false;
        ++wide; ++narrow;
    }
    return *wide == 0 && *narrow == 0;
}

bool NameEqualsA(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (ToLowerAscii(*a) != ToLowerAscii(*b)) return false;
        ++a; ++b;
    }
    return *a == 0 && *b == 0;
}

} 

HMODULE DynGetModuleHandle(const char* moduleName) {
#if defined(_M_X64) || defined(__x86_64__)
    PPEB_FULL pPeb = (PPEB_FULL)__readgsqword(0x60);
#else
    PPEB_FULL pPeb = (PPEB_FULL)__readfsdword(0x30);
#endif
    if (!pPeb || !pPeb->Ldr) return nullptr;
    PPEB_LDR_DATA_FULL pLdr = pPeb->Ldr;

    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    for (PLIST_ENTRY e = pListHead->Flink; e != pListHead; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY_FULL pEntry =
            CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);
        if (pEntry->DllBase && pEntry->BaseDllName.Buffer &&
            NameEqualsNarrow(pEntry->BaseDllName.Buffer, moduleName)) {
            return (HMODULE)pEntry->DllBase;
        }
    }
    return nullptr;
}

FARPROC DynGetProcAddress(HMODULE moduleBase, const char* funcName) {
    if (!moduleBase || !funcName) return nullptr;
    BYTE* pBase = (BYTE*)moduleBase;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    DWORD exportRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return nullptr;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportRva);
    DWORD* pNames = (DWORD*)(pBase + pExport->AddressOfNames);
    WORD* pOrdinals = (WORD*)(pBase + pExport->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)(pBase + pExport->AddressOfFunctions);

    for (DWORD i = 0; i < pExport->NumberOfNames; ++i) {
        const char* name = (const char*)(pBase + pNames[i]);
        if (NameEqualsA(name, funcName)) {
            DWORD funcRva = pFunctions[pOrdinals[i]];

            DWORD exportSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            if (funcRva >= exportRva && funcRva < exportRva + exportSize) return nullptr;
            return (FARPROC)(pBase + funcRva);
        }
    }
    return nullptr;
}

typedef NTSTATUS(NTAPI* pLdrLoadDll)(PWSTR, PULONG, UNICODE_STRING*, PHANDLE);

HMODULE DynLoadLibrary(const WCHAR* moduleName) {
    if (!moduleName) return nullptr;
    static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
    static constexpr auto obfLdrLoadDll = MAKE_OBF("LdrLoadDll");
    HMODULE hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll));
    if (!hNtdll) return nullptr;
    pLdrLoadDll fn = (pLdrLoadDll)DynGetProcAddress(hNtdll, DECR_STR(obfLdrLoadDll));
    if (!fn) return nullptr;

    size_t len = 0;
    while (moduleName[len]) ++len;

    UNICODE_STRING us;
    us.Length = (USHORT)(len * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);
    us.Buffer = (PWSTR)moduleName;

    HANDLE hMod = nullptr;
    NTSTATUS status = fn(nullptr, nullptr, &us, &hMod);
    return NT_SUCCESS(status) ? (HMODULE)hMod : nullptr;
}
