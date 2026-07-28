#ifndef THIRDEYE_INTERNAL_H
#define THIRDEYE_INTERNAL_H

#include <windows.h>
#include <cstring>

#include "sbox_shred.h"

#define MAKE_OBF(str) SHRED(str)
#define DECR_STR(obf) REVEAL_CSTR(obf)

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

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

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
static inline bool SafeCopyString(char (&dest)[N], const char* src) {
    size_t len = strlen(src);
    if (len >= N) return false;
    memcpy(dest, src, len + 1);
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

#define REMOTE_SECTION_NAME ".text$mn"
#ifdef __GNUC__
#define SEC_REMOTE __attribute__((section(REMOTE_SECTION_NAME)))
#define FUNC_ATTRS __attribute__((no_instrument_function, optimize("O0"), force_align_arg_pointer))
#else
#pragma section(REMOTE_SECTION_NAME, read, execute)
#define SEC_REMOTE
#define FUNC_ATTRS
#endif

#ifndef __GNUC__
#pragma code_seg(push, remote_seg, REMOTE_SECTION_NAME)
#endif
extern "C" SEC_REMOTE FUNC_ATTRS DWORD __stdcall RemoteThreadProc(LPVOID lpParameter);
extern "C" SEC_REMOTE FUNC_ATTRS void __stdcall RemoteThreadProcEnd();
#ifndef __GNUC__
#pragma code_seg(pop, remote_seg)
#endif

struct ThirdeyeContext {
    char lastError[256];
};

void SetLastErrorMsg(ThirdeyeContext* ctx, const char* msg);

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

// Minimal REPARSE_DATA_BUFFER for mount-point junctions (WIN32_LEAN_AND_MEAN).
#ifndef THIRDEYE_HAS_TE_REPARSE
#define THIRDEYE_HAS_TE_REPARSE
typedef struct _TE_REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    };
} TE_REPARSE_DATA_BUFFER, *PTE_REPARSE_DATA_BUFFER;
#endif

#ifndef REPARSE_DATA_BUFFER
#define REPARSE_DATA_BUFFER TE_REPARSE_DATA_BUFFER
#define PREPARSE_DATA_BUFFER PTE_REPARSE_DATA_BUFFER
#endif

// ---------------------------------------------------------------------------
// Elevated worker IPC (Method 83 bootstraps once; captures are on-demand).
// Medium IL creates the section + events (Low integrity label so High IL can
// open/signal them). The elevated rundll32 worker stays resident.
// IPC object names and the staging path are shredded at use sites (not stored
// as plaintext literals in the binary).
// ---------------------------------------------------------------------------
#define THIRDEYE_SESSION_CMD_NONE     0
#define THIRDEYE_SESSION_CMD_CAPTURE  1
#define THIRDEYE_SESSION_CMD_SHUTDOWN 2

#define THIRDEYE_SESSION_STATUS_IDLE  0
#define THIRDEYE_SESSION_STATUS_OK    1
#define THIRDEYE_SESSION_STATUS_FAIL  2
#define THIRDEYE_SESSION_STATUS_READY 3

typedef struct _THIRDEYE_SESSION_SHM {
    volatile LONG status;
    volatile LONG cmd;
    DWORD         helperPid;
    DWORD         format;
    DWORD         quality;
    DWORD         inclusive;
    wchar_t       outPath[MAX_PATH];
} THIRDEYE_SESSION_SHM;

#define THIRDEYE_ELEV_CMD_NONE         THIRDEYE_SESSION_CMD_NONE
#define THIRDEYE_ELEV_CMD_CAPTURE      THIRDEYE_SESSION_CMD_CAPTURE
#define THIRDEYE_ELEV_CMD_SHUTDOWN     THIRDEYE_SESSION_CMD_SHUTDOWN
#define THIRDEYE_ELEV_STATUS_IDLE      THIRDEYE_SESSION_STATUS_IDLE
#define THIRDEYE_ELEV_STATUS_OK        THIRDEYE_SESSION_STATUS_OK
#define THIRDEYE_ELEV_STATUS_FAIL      THIRDEYE_SESSION_STATUS_FAIL
#define THIRDEYE_ELEV_STATUS_READY     THIRDEYE_SESSION_STATUS_READY
typedef THIRDEYE_SESSION_SHM THIRDEYE_ELEVATED_SHM;

bool Uc83EnsureElevatedWorker(void);
bool Uc83RequestElevatedCapture(const wchar_t* absPath, DWORD format, DWORD quality, DWORD inclusive);
bool Uc83ShutdownElevatedWorker(void);
bool Uc83QuerySessionState(int* readyOut, DWORD* pidOut);
void TeSessionMain(void);

// Client ownership for RAII teardown on host process exit.
void TeMarkClientPrepared(bool prepared);
bool TeClientOwnsSession(void);
bool TeSessionArmed(void);
extern "C" void TeAutoCleanIfOwned(void);

#endif
