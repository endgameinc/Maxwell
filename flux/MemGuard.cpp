#include "MemGuard.h"
#include "log.h"
#include "ntapi.h"
#include <stdio.h>

void * guardList[20];
int gCount = 0;
extern const char *g_baseExe;

void PageGuard(void * Addr)
{
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(Addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    if (mbi.State == MEM_COMMIT)
    {
        if (!(mbi.Protect & PAGE_GUARD))
        {
            DWORD flNewProtect = 0;
            DWORD flOldProtect = 0;
            flNewProtect = mbi.Protect | PAGE_GUARD;
            VirtualProtect(Addr, 0x1000, flNewProtect, &flOldProtect);
        }
    }
}

DWORD WINAPI GuardThread(
	_In_ LPVOID lpParameter
	)
{
	while (1)
	{
		for (int i = 0; i < gCount; i++)
		{
			PageGuard(guardList[i]);
		}
		Sleep(10);
	}
}

void * ModuleEAT(DWORD_PTR base)
{
	IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *)base;

	IMAGE_NT_HEADERS * pNtHeader = (IMAGE_NT_HEADERS *)((DWORD)pDosHeader->e_lfanew + base);

	IMAGE_EXPORT_DIRECTORY * pExport = (IMAGE_EXPORT_DIRECTORY *)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);

	return (void*)(pExport->Name + base);
}

void * ModuleIAT(DWORD_PTR base)
{
	IMAGE_DOS_HEADER * pDosHeader = (IMAGE_DOS_HEADER *)base;

	IMAGE_NT_HEADERS * pNtHeader = (IMAGE_NT_HEADERS *)((DWORD)pDosHeader->e_lfanew + base);

	IMAGE_IMPORT_DESCRIPTOR * pImport = (IMAGE_IMPORT_DESCRIPTOR *)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + base);

	return (void*)(pImport->Name + base);
}

LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
	)
{
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		wchar_t modSource[MAX_PATH];
        wchar_t modTarget[MAX_PATH];

		if (MaxLog::AddressToModule((DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionInformation[1], modTarget, MAX_PATH))
		{
            MaxLog::AddressToModule((DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, modSource, MAX_PATH);

			MEMORY_BASIC_INFORMATION lpBuffer;
			memset(&lpBuffer, '\0', sizeof(MEMORY_BASIC_INFORMATION));
			VirtualQuery((void*)ExceptionInfo->ExceptionRecord->ExceptionAddress, &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION));

			// we could even get more granular with this, and white list specific functions
			if ((lpBuffer.State & MEM_COMMIT) && wcscmp(modSource, L"ntdll.dll") != 0 
                && wcscmp(modSource, L"IEShims.dll") != 0
                && wcscmp(modSource, L"apphelp.dll") != 0 
                && wcscmp(modSource, L"msvcrt.dll") != 0
                && wcscmp(modSource, L"shlwapi.dll") != 0)
			{
				LOG("suuppp", "EAF", "GuardPage", "ModSource", modSource, "ModTarget", modTarget, "SourceAddress", (DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, "TargetAddres", (DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionInformation[1], "MemType", lpBuffer.Type);

				char outFile[MAX_PATH];
				sprintf_s(outFile, MAX_PATH, "C:\\%s_EAF_%x", MaxLog::g_baseExe, lpBuffer.BaseAddress);

                //LOG("sb", "FileName", outFile, "FileData", lpBuffer.BaseAddress, lpBuffer.RegionSize);
         
				HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
				if (hFile != INVALID_HANDLE_VALUE)
				{
					DWORD dWritten = 0;
					WriteFile(hFile, lpBuffer.BaseAddress, lpBuffer.RegionSize, &dWritten, 0);
					CloseHandle(hFile);
				}
                    

			}
		}

		// Virtual Query ExceptionAddress, see if its outside MEM_IMAGE, or other sketchy address
		// Or maybe just whitelist the areas it normally comes from


		return EXCEPTION_CONTINUE_EXECUTION;

	}
	else if (ExceptionInfo->ExceptionRecord->ExceptionCode >= STATUS_ACCESS_VIOLATION && ExceptionInfo->ExceptionRecord->ExceptionCode <= STATUS_SXS_INVALID_DEACTIVATION)
	{
		/* Uncomment this to enable logging of crashes/access violations/etc */
        //LOG("ll", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "ExceptionAddress", ExceptionInfo->ExceptionRecord->ExceptionAddress);

		wchar_t modSource[MAX_PATH];
        MaxLog::AddressToModule((DWORD_PTR)ExceptionInfo->ExceptionRecord->ExceptionAddress, modSource, MAX_PATH);
        if (_wcsicmp(modSource, L"kernel32.dll") != 0 && _wcsicmp(modSource, L"kernelbase.dll") != 0)
        //if ( _wcsicmp(modSource, L"flux32.dll") == 0 )
        {
            LOG("xu", "ExceptionCode", ExceptionInfo->ExceptionRecord->ExceptionCode, "Module", modSource);
        }

	}
	return EXCEPTION_CONTINUE_SEARCH;
	//return EXCEPTION_EXECUTE_HANDLER;
}

PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2)
{
    const wchar_t *s1, *s2;
    const wchar_t l = towlower(*wcs2);
    const wchar_t u = towupper(*wcs2);

    if (!*wcs2)
        return wcs1;

    for (; *wcs1; ++wcs1)
    {
        if (*wcs1 == l || *wcs1 == u)
        {
            s1 = wcs1 + 1;
            s2 = wcs2 + 1;

            while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
                ++s1, ++s2;

            if (!*s2)
                return wcs1;
        }
    }

    return NULL;
}


VOID CALLBACK LdrDllNotification(
    _In_     ULONG                       NotificationReason,
    _In_     PLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID                       Context
    )
{
    if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        //printf("Loaded %ws\n", NotificationData->Loaded.BaseDllName->Buffer);
        if (wcsistr(NotificationData->Loaded.BaseDllName->Buffer, L"flash"))
        {
            //LOG("s", "Flash", "Loaded");
            // Protect flash IAT
            guardList[gCount] = ModuleIAT((DWORD_PTR)NotificationData->Loaded.DllBase);
            gCount++;
            
            // We could also protect MZ header, but would need to filter flash._ValidateImageBase()
            // http://www.bigmessowires.com/2015/10/02/what-happens-before-main/. 

        }
    }

}
// http://phrack.org/issues/63/15.html - shellcode techniques/detections

void InitEAF()
{
	AddVectoredExceptionHandler(0, VectoredHandler);

	// Get memory location of kernel32
	DWORD_PTR kernel32 = (DWORD_PTR)GetModuleHandle(L"kernel32.dll");
	// Protect MZ header
	guardList[gCount] = (void*)kernel32;
	gCount++;
	// Protect Export Address Table
	guardList[gCount] = ModuleEAT(kernel32);
	gCount++;
	// Protect Imports
	guardList[gCount] = ModuleIAT(kernel32);
	gCount++;

	DWORD_PTR ntdll = (DWORD_PTR)GetModuleHandle(L"ntdll.dll");
	// Protect MZ header
	guardList[gCount] = (void*)ntdll;
	gCount++;
	// Protect Export Address Table
	guardList[gCount] = ModuleEAT(ntdll);
	gCount++;
	// Protect Imports
	guardList[gCount] = ModuleIAT(ntdll);
	gCount++;

	DWORD_PTR kernelbase = (DWORD_PTR)GetModuleHandle(L"kernelbase.dll");
	// Protect MZ header
	guardList[gCount] = (void*)kernelbase;
	gCount++;
	// Protect Export Address Table
	guardList[gCount] = ModuleEAT(kernelbase);
	gCount++;
	// Protect Imports
	guardList[gCount] = ModuleIAT(kernelbase);
	gCount++;

    /*
    race condition w/ IE associated with this- iexplore.exe Exception Source: rpcrt4.dll Code: 0xC0020043
    if (strcmp(MaxLog::g_baseExe, "iexplore.exe") == 0)
    {
        // Will need to filter msvcrt.dll for this
        // Protect MZ header
        guardList[gCount] = (void*)GetModuleHandle(0);
        gCount++;
    }
    */

    _LdrRegisterDllNotification LdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrRegisterDllNotification");
    if (LdrRegisterDllNotification)
    {
        void * cookie;
        LdrRegisterDllNotification(0, LdrDllNotification, 0, &cookie);
    }
    CreateThread(0, 0, GuardThread, 0, 0, 0);
}
