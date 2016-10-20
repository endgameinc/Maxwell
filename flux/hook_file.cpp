#include <stdio.h>
#include <Shlobj.h>
#include "hook.h"
#include "ntapi.h"
#include "log.h"
#include "whitelist.h"

typedef NTSTATUS(NTAPI * pNtQueryInformationFile)(
	HANDLE FileHandle,
    PVOID IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass);

typedef NTSTATUS(NTAPI * pNtCreateFile)(
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

bool HandleToFilePath(HANDLE FileHandle, char * filePath,wchar_t * widefilePath, int size)
{
	char iosb[256];
    char buffer[MAX_PATH * 2];

	FILE_NAME_INFORMATION * fileNameInfo = (FILE_NAME_INFORMATION *)buffer;
	ZeroMemory(fileNameInfo, MAX_PATH * 2);
	// FileNameInformation = 9
	pNtQueryInformationFile  NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryInformationFile");
	if (NtQueryInformationFile)
	{

		NTSTATUS status = NtQueryInformationFile(FileHandle, &iosb, fileNameInfo, MAX_PATH * 2, FileNameInformation);
		if (status == STATUS_SUCCESS)
		{
			size_t ReturnValue;
			int retVal = wcstombs_s(&ReturnValue, filePath, size, fileNameInfo->FileName,size);
			wcscpy_s(widefilePath, 512, fileNameInfo->FileName);
			if (ReturnValue > 0 && retVal == 0)
				return true;
			else
				return false;
		}
	}

	return false;


}


/* ToDo:
Walk callstack for things outside loaded modules, should be able to detect shellcode dropping files. 
*/
NTSTATUS(WINAPI * OldNtWriteFile)
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
    )
{
	try
	{
		NTSTATUS retVal = OldNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
		if (retVal == STATUS_SUCCESS && Length > 0)
		{
			char filePath[512];
			wchar_t widefilePath[512];
			if (HandleToFilePath(FileHandle, filePath, widefilePath, 512))
			{
				if (!IsFilePathWhitelisted(widefilePath, wcslen(widefilePath)))
				{
                    LOG("slb", "FileName", filePath, "Length", Length, "FileData", Buffer, Length);
				}
			}
		}
		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtWriteFile");
		return -1;
	}
}

bool MemSearch(void * needle, SIZE_T needleSize, void * haystack, SIZE_T haystackSize)
{
	if (needleSize > haystackSize)
		return false;

	for (SIZE_T i = 0; i <= haystackSize - needleSize; i++)
	{
		if (memcmp((char*)haystack + i, needle, needleSize) == 0)
			return true;
	}

	return false;

}

const wchar_t * VMDetect[] =
{
    L"TPAutoConnSvc"
    L"Bitdefender Agent",
    L"ESET NOD32 Antivirus",
    L"\\FFDec\\"
    L"Wireshark",
    L"Fiddler",
    //L"VMware Tools", possible whiteops FP
    //L"VirtualBox Guest Additions", possible whiteops FP

};

NTSTATUS(WINAPI *OldNtCreateFile)
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
    )
{
	try
	{
		if (ObjectAttributes)
		{
			if (ObjectAttributes->ObjectName)
			{
				if (ObjectAttributes->ObjectName->Buffer)
				{
                    for (int i = 0; i < ARRAYSIZE(VMDetect); i++)
                    {
                        if (MemSearch((void*)VMDetect[i], wcslen(VMDetect[i]) * 2, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length))
                        {
                            LOG("o", "VMDetect", ObjectAttributes->ObjectName);
                        }
                    }
				}
			}
		}
		NTSTATUS retVal = OldNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

		
		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtCreateFile");
		return -1;
	}
}

NTSTATUS(WINAPI * OldNtQueryAttributesFile)
(
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
    );

NTSTATUS WINAPI MyNtQueryAttributesFile
(
    POBJECT_ATTRIBUTES      ObjectAttributes,
    PFILE_BASIC_INFORMATION FileInformation
    )
{

	try
	{
		if (ObjectAttributes)
		{
			if (ObjectAttributes->ObjectName)
			{
				if (ObjectAttributes->ObjectName->Buffer)
				{
                    for (int i = 0; i < ARRAYSIZE(VMDetect); i++)
                    {
                        if (MemSearch((void*)VMDetect[i], wcslen(VMDetect[i]) * 2, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length))
                        {
                            LOG("o", "VMDetect", ObjectAttributes->ObjectName);
                        }
                    }
				}
			}
		}
		NTSTATUS retVal = OldNtQueryAttributesFile(ObjectAttributes, FileInformation);

		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtQueryAttributesFile");
		return -1;
	}

}