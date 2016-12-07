#pragma once
#include "ntapi.h"

extern NTSTATUS(WINAPI * OldNtSetValueKey)
(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
    );

NTSTATUS WINAPI MyNtSetValueKey
(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);

extern NTSTATUS(WINAPI * OldNtOpenKeyEx)
(
    PHANDLE            KeyHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG              OpenOptions
    );

NTSTATUS WINAPI MyNtOpenKeyEx
(
    PHANDLE            KeyHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG              OpenOptions
);


extern NTSTATUS(NTAPI * OldNtCreateUserProcess)
(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    void * CreateInfo,
    void * AttributeList
    );

NTSTATUS NTAPI MyNtCreateUserProcess
(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    POBJECT_ATTRIBUTES ProcessObjectAttributes,
    POBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    void * CreateInfo,
    void * AttributeList
);


extern NTSTATUS(WINAPI * OldNtCreateProcess)
(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
    );

NTSTATUS WINAPI MyNtCreateProcess
(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    BOOLEAN InheritObjectTable,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort
);


extern NTSTATUS(WINAPI * OldNtCreateProcessEx)
(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
    );

NTSTATUS WINAPI MyNtCreateProcessEx
(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

extern NTSTATUS(WINAPI * OldNtDelayExecution)
(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
    );
NTSTATUS WINAPI MyNtDelayExecution
(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);


extern NTSTATUS(WINAPI * OldNtProtectVirtualMemory)
(
    HANDLE               ProcessHandle,
    PVOID            *BaseAddress,
    PULONG           NumberOfBytesToProtect,
    ULONG                NewAccessProtection,
    PULONG              OldAccessProtection
    );

NTSTATUS WINAPI MyNtProtectVirtualMemory
(
    HANDLE               ProcessHandle,
    PVOID            *BaseAddress,
    PULONG           NumberOfBytesToProtect,
    ULONG                NewAccessProtection,
    PULONG              OldAccessProtection
);

extern NTSTATUS(WINAPI * OldNtFreeVirtualMemory)
(
    HANDLE  ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
    );

NTSTATUS WINAPI MyNtFreeVirtualMemory
(
    HANDLE  ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

extern NTSTATUS(WINAPI * OldNtWriteFile)
(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PVOID IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

NTSTATUS WINAPI MyNtWriteFile
(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PVOID IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

extern NTSTATUS(WINAPI *OldNtCreateFile)
(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

NTSTATUS WINAPI MyNtCreateFile
(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PVOID IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);


extern NTSTATUS(WINAPI * OldNtQueryAttributesFile)
(
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
    );

NTSTATUS WINAPI MyNtQueryAttributesFile
(
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
);

typedef struct
{
    wchar_t * libName;
    char * functionName;
    void * myFunc;
    void ** oldFunc;
} Hook;

void InstallHook(Hook * hook);
