.intel_syntax noprefix
.text

.globl g_SysNtOpenProcess
.globl g_SysNtAllocateVirtualMemory
.globl g_SysNtWriteVirtualMemory
.globl g_SysNtFreeVirtualMemory
.globl g_SysNtCreateThreadEx
.globl g_SysNtClose
.globl g_SysNtQueryInformationProcess
.globl g_SysNtWaitForSingleObject
.globl g_SysNtProtectVirtualMemory
.globl g_SysNtOpenThread
.globl g_SysNtSuspendThread
.globl g_SysNtResumeThread
.globl g_SysNtGetContextThread
.globl g_SysNtSetContextThread

.data
g_SysNtOpenProcess:             .long 0
g_SysNtAllocateVirtualMemory:   .long 0
g_SysNtWriteVirtualMemory:      .long 0
g_SysNtFreeVirtualMemory:       .long 0
g_SysNtCreateThreadEx:          .long 0
g_SysNtClose:                   .long 0
g_SysNtQueryInformationProcess: .long 0
g_SysNtWaitForSingleObject:     .long 0
g_SysNtProtectVirtualMemory:    .long 0
g_SysNtOpenThread:              .long 0
g_SysNtSuspendThread:           .long 0
g_SysNtResumeThread:            .long 0
g_SysNtGetContextThread:        .long 0
g_SysNtSetContextThread:        .long 0

.text

# ==============================================================================
# Windows x64 syscall convention:
#   - eax  = syscall number
#   - r10  = arg1 (rcx is clobbered by syscall instruction)
#   - rdx  = arg2
#   - r8   = arg3
#   - r9   = arg4
#   - stack: [rsp+0x28]=arg5, [rsp+0x30]=arg6, etc.
#
# Windows x64 calling convention:
#   - rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4
#   - stack: [rsp+0x28]=arg5, [rsp+0x30]=arg6, etc.
#   - Caller allocates 32-byte shadow space before call
# ==============================================================================

# NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, 
#               POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
# 4 args: rcx, rdx, r8, r9
.globl SyscallNtOpenProcess
SyscallNtOpenProcess:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtOpenProcess]
    syscall
    ret

# NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
#                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
# 6 args: rcx, rdx, r8, r9, [rsp+0x28], [rsp+0x30]
.globl SyscallNtAllocateVirtualMemory
SyscallNtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtAllocateVirtualMemory]
    syscall
    ret

# NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
#                      SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
# 5 args: rcx, rdx, r8, r9, [rsp+0x28]
.globl SyscallNtWriteVirtualMemory
SyscallNtWriteVirtualMemory:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtWriteVirtualMemory]
    syscall
    ret

# NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
# 4 args: rcx, rdx, r8, r9
.globl SyscallNtFreeVirtualMemory
SyscallNtFreeVirtualMemory:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtFreeVirtualMemory]
    syscall
    ret

# NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
#                  HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
#                  SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
# 11 args: rcx, rdx, r8, r9, then 7 more on stack
.globl SyscallNtCreateThreadEx
SyscallNtCreateThreadEx:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtCreateThreadEx]
    syscall
    ret

# NtClose(HANDLE Handle)
# 1 arg: rcx
.globl SyscallNtClose
SyscallNtClose:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtClose]
    syscall
    ret

# NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
#                           PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
# 5 args: rcx, rdx, r8, r9, [rsp+0x28]
.globl SyscallNtQueryInformationProcess
SyscallNtQueryInformationProcess:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtQueryInformationProcess]
    syscall
    ret

# NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
# 3 args: rcx, rdx, r8
.globl SyscallNtWaitForSingleObject
SyscallNtWaitForSingleObject:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtWaitForSingleObject]
    syscall
    ret

# NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, 
#                        ULONG NewProtect, PULONG OldProtect)
# 5 args: rcx, rdx, r8, r9, [rsp+0x28]
.globl SyscallNtProtectVirtualMemory
SyscallNtProtectVirtualMemory:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtProtectVirtualMemory]
    syscall
    ret

# NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
#              POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
# 4 args: rcx, rdx, r8, r9
.globl SyscallNtOpenThread
SyscallNtOpenThread:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtOpenThread]
    syscall
    ret

# NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
# 2 args: rcx, rdx
.globl SyscallNtSuspendThread
SyscallNtSuspendThread:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtSuspendThread]
    syscall
    ret

# NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
# 2 args: rcx, rdx
.globl SyscallNtResumeThread
SyscallNtResumeThread:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtResumeThread]
    syscall
    ret

# NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
# 2 args: rcx, rdx
.globl SyscallNtGetContextThread
SyscallNtGetContextThread:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtGetContextThread]
    syscall
    ret

# NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
# 2 args: rcx, rdx
.globl SyscallNtSetContextThread
SyscallNtSetContextThread:
    mov r10, rcx
    mov eax, dword ptr [rip + g_SysNtSetContextThread]
    syscall
    ret
