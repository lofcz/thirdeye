#ifndef THIRDEYE_INTERNAL_H
#define THIRDEYE_INTERNAL_H

#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <cstring>

constexpr unsigned char OBF_SEED = (__TIME__[7] ^ __TIME__[4] ^ __TIME__[1]) & 0xFF;

constexpr unsigned char GenKey(unsigned char idx, unsigned char seed) {
    return ((seed + idx) ^ ((idx * 7) + 0x41)) & 0xFF;
}

template<size_t N, unsigned char SEED>
struct ObfString {
    unsigned char data[N];

    constexpr explicit ObfString(const char(&str)[N]) : data{} {
        for (unsigned char i = 0; i < N; ++i) {
            data[i] = static_cast<unsigned char>(str[i]) ^ GenKey(i, SEED);
        }
    }

    template<size_t M>
    bool deobfuscate(char (&out)[M]) const {
        if (M < N) return false;
        for (unsigned char i = 0; i < N; ++i) {
            out[i] = static_cast<char>(data[i] ^ GenKey(i, SEED));
        }
        return true;
    }

    [[nodiscard]] std::string str() const {
        char buf[N];
        deobfuscate(buf);
        return std::string(buf);
    }
};

#define MAKE_OBF(str) ObfString<sizeof(str), OBF_SEED>(str)
#define DECR_STR(obf) (obf).str()

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

extern "C" {
    extern DWORD g_SysNtOpenProcess;
    extern DWORD g_SysNtAllocateVirtualMemory;
    extern DWORD g_SysNtWriteVirtualMemory;
    extern DWORD g_SysNtFreeVirtualMemory;
    extern DWORD g_SysNtCreateThreadEx;
    extern DWORD g_SysNtClose;
    extern DWORD g_SysNtQueryInformationProcess;
    extern DWORD g_SysNtWaitForSingleObject;
    extern DWORD g_SysNtProtectVirtualMemory;
}

extern "C" {
    NTSTATUS SyscallNtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS SyscallNtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS SyscallNtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS SyscallNtFreeVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG FreeType
    );

    NTSTATUS SyscallNtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PPS_ATTRIBUTE_LIST AttributeList
    );

    NTSTATUS SyscallNtClose(HANDLE Handle);

    NTSTATUS SyscallNtQueryInformationProcess(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    NTSTATUS SyscallNtWaitForSingleObject(
        HANDLE Handle,
        BOOLEAN Alertable,
        PLARGE_INTEGER Timeout
    );

    NTSTATUS SyscallNtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
}

HMODULE GetNtdllHandle();
DWORD GetSyscallNumber(const char* funcName);
bool InitializeSyscalls();

HANDLE NtOpenProcessDirect(DWORD pid, ACCESS_MASK desiredAccess);
PVOID NtAllocateMemoryDirect(HANDLE hProcess, SIZE_T size, ULONG protect);
bool NtWriteMemoryDirect(HANDLE hProcess, PVOID dest, PVOID src, SIZE_T size);
void NtFreeMemoryDirect(HANDLE hProcess, PVOID addr);
HANDLE NtCreateThreadDirect(HANDLE hProcess, PVOID startAddr, PVOID param);
void NtCloseDirect(HANDLE handle);
bool NtProtectMemoryDirect(HANDLE hProcess, PVOID addr, SIZE_T size, ULONG newProtect, PULONG oldProtect);
DWORD NtWaitDirect(HANDLE handle, DWORD milliseconds);

int GetEncoderClsid(const WCHAR* format, CLSID* pClsid);
size_t GetRemoteSectionSize();

typedef DWORD(WINAPI* pWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL(WINAPI* pReleaseSemaphore)(HANDLE, LONG, LPLONG);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef struct _PEB_LDR_DATA_FULL {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_FULL, *PPEB_LDR_DATA_FULL;

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL, *PLDR_DATA_TABLE_ENTRY_FULL;

typedef struct _PEB_FULL {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA_FULL Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
} PEB_FULL, *PPEB_FULL;

typedef NTSTATUS(NTAPI* pRtlEnterCriticalSection)(PRTL_CRITICAL_SECTION);
typedef NTSTATUS(NTAPI* pRtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION);

#define MAX_HWNDS_PER_PID 256
#define MAX_FUNC_NAME 128

struct INJECTION_DATA {
    DWORD count;
    HWND hwnds[MAX_HWNDS_PER_PID];
    DWORD originalAffinities[MAX_HWNDS_PER_PID];

    HANDLE hGlobalTriggerEvent;
    HANDLE hReadySemaphore;

    char libName[MAX_FUNC_NAME];
    char setFuncName[MAX_FUNC_NAME];
    char getFuncName[MAX_FUNC_NAME];
    char kernel32Name[MAX_FUNC_NAME];
    char ntdllName[MAX_FUNC_NAME];
    char waitFuncName[MAX_FUNC_NAME];
    char releaseFuncName[MAX_FUNC_NAME];
    char getModuleFuncName[MAX_FUNC_NAME];
    char getProcFuncName[MAX_FUNC_NAME];
    char enterCritSecName[MAX_FUNC_NAME];
    char leaveCritSecName[MAX_FUNC_NAME];
};

template<size_t N>
static inline bool SafeCopyString(char (&dest)[N], const std::string& src) {
    if (src.length() >= N) return false;
    memcpy(dest, src.c_str(), src.length() + 1);
    return true;
}

struct RemoteContext {
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID pRemoteData;
    LPVOID pRemoteCode;
    DWORD pid;
};

class HandleGuard {
    HANDLE m_handle;
public:
    explicit HandleGuard(HANDLE h = nullptr) : m_handle(h) {}
    ~HandleGuard() { if (m_handle) CloseHandle(m_handle); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) { other.m_handle = nullptr; }
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            if (m_handle) CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const { return m_handle; }
    explicit operator bool() const { return m_handle != nullptr; }
};

#ifdef __GNUC__
#define SEC_REMOTE __attribute__((section(".remote")))
#define FUNC_ATTRS __attribute__((no_instrument_function, optimize("O0"), force_align_arg_pointer))
#else
#pragma section(".remote", read, execute)
#define SEC_REMOTE __declspec(allocate(".remote"))
#define FUNC_ATTRS
#endif

extern "C" SEC_REMOTE FUNC_ATTRS DWORD __stdcall RemoteThreadProc(LPVOID lpParameter);

struct ThirdeyeContext {
    char lastError[256];
};

void SetLastErrorMsg(ThirdeyeContext* ctx, const char* msg);

#endif

