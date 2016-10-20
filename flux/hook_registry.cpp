#include "hook.h"
#include "ntapi.h"
#include "log.h"

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

typedef struct _KEY_NAME_INFORMATION {
	ULONG NameLength;
	WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;


bool HandleToKey(HANDLE hKey, char * keyPath)
{
	typedef DWORD(__stdcall *pNtQueryKey)(
			HANDLE  KeyHandle,
			int KeyInformationClass,
			PVOID  KeyInformation,
			ULONG  Length,
			PULONG  ResultLength);

	pNtQueryKey NtQueryKey = (pNtQueryKey)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryKey");

	if (NtQueryKey)
	{
		DWORD size = 0;
		DWORD result = 0;
		result = NtQueryKey(hKey, 3, 0, 0, &size);
		if (result == STATUS_BUFFER_TOO_SMALL)
		{
			size = size + 2;
			KEY_NAME_INFORMATION * buffer = (KEY_NAME_INFORMATION*)malloc(size); // size is in bytes
			ZeroMemory(buffer, size);
			if (buffer != NULL)
			{
				result = NtQueryKey(hKey, 3, buffer, size, &size);
				if (result == STATUS_SUCCESS)
				{
					size_t ReturnValue;
					wcstombs_s(&ReturnValue, keyPath, 500, buffer->Name, 500);
				}
			}
			if (buffer)
				free(buffer);
		}
	}

	return false;
}

NTSTATUS(WINAPI * OldNtSetValueKey)
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
    )
{
	try
	{
		NTSTATUS retVal = OldNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
		if (retVal == STATUS_SUCCESS && Type == REG_SZ)
		{
			char keyPath[512];
			HandleToKey(KeyHandle, keyPath);
			LOG("sU", "KeyPath", keyPath, "KeyValue", Data, DataSize);
		}
		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtSetValueKey");
		return -1;
	}
}

extern bool MemSearch(void * needle, SIZE_T needleSize, void * haystack, SIZE_T haystackSize);

NTSTATUS (WINAPI * OldNtOpenKeyEx)
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
					if (MemSearch(L"Kaspersky", sizeof(L"Kaspersky") - 2, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length))
					{
						LOG("o", "VMDetect", ObjectAttributes->ObjectName);
					}
					if (MemSearch(L"IeVirtualKeyboardPlugin", sizeof(L"IeVirtualKeyboardPlugin") - 2, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length))
					{
						LOG("o", "VMDetect", ObjectAttributes->ObjectName);
					}

				}
			}
		}
		NTSTATUS retVal = OldNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);

		return retVal;
	}
	catch (...)
	{
		LOG("s", "Exception", "NtOpenKey");
		return -1;
	}

}


