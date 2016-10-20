#include "hook.h"
#include "ntapi.h"
#include "log.h"
#include <Psapi.h>
#include <stdio.h>
#include "DbgHelp.h"
#include <TlHelp32.h>
#include "whitelist.h"

#pragma comment(lib, "DbgHelp.lib")

// Good Reading - http://www.fuzzysecurity.com/tutorials/expDev/7.html

// Exception handler wrappers around these functions for https://blogs.mcafee.com/mcafee-labs/recent-ie-0-day-unusual-case-study

// ROP Detection and Bypass http://vulnfactory.org/blog/2011/09/21/defeating-windows-8-rop-mitigation/ . Alternate method, memcpy rop chain to stack

// Good overview of Heap Exploits - https://www.corelan.be/index.php/2011/12/31/exploit-writing-tutorial-part-11-heap-spraying-demystified/#Heap_Spraying_on_IE10_8211_Windows_8

// Good paper about EMET - https://bromiumlabs.files.wordpress.com/2014/02/bypassing-emet-4-1.pdf

// KBouncer - http://www.cs.columbia.edu/~vpappas/papers/kbouncer.pdf

/*
EMET Critical functions - http://0xdabbad00.com/wp-content/uploads/2013/11/emet_4_1_uncovered.pdf
kernel32.MapViewOfFileFromApp
ntdll.NtMapViewOfSection
kernelbase.MapViewOfFileEx
kernelbase.MapViewOfFile
kernel32.MapViewOfFileEx
kernel32.MapViewOfFile
ntdll.NtCreateSection
kernelbase.CreateFileMappingW
kernelbase.CreateFileMappingNumaW
kernel32.CreateFileMappingW
kernel32.CreateFileMappingA
ntdll.NtCreateFile
kernelbase.CreateFileW
kernel32.CreateFileW
kernel32.CreateFileA
kernel32.WinExec
ntdll.NtWriteVirtualMemory
kernelbase.WriteProcessMemory
kernel32.WriteProcessMemory
ntdll.NtCreateThreadEx
kernelbase.CreateRemoteThreadEx
kernel32.CreateRemoteThreadEx
kernel32.CreateRemoteThread
ntdll.NtCreateProcess
ntdll.NtCreateUserProcess
kernel32.CreateProcessInternalW
kernel32.CreateProcessInternalA
kernel32.CreateProcessW
kernel32.CreateProcessA
ntdll.RtlCreateHeap
kernelbase.HeapCreate
kernel32.HeapCreate
ntdll.NtAllocateVirtualMemory
kernelbase.VirtualAllocEx
kernelbase.VirtualAlloc
kernel32.VirtualAllocEx
kernel32.VirtualAlloc
ntdll.LdrLoadDll
kernelbase.LoadLibraryExW
kernelbase.LoadLibraryExA
kernel32.LoadPackagedLibrary
kernel32.LoadLibraryExW
kernel32.LoadLibraryExA
kernel32.LoadLibraryW
kernel32.LoadLibraryA
ntdll.NtProtectVirtualMemory
kernelbase.VirtualProtectEx
kernelbase.VirtualProtect
kernel32.VirtualProtectEx
kernel32.VirtualProtect
ntdll.LdrHotPatchRoutine

*/
extern CRITICAL_SECTION cs;

// Detects stack pivot type behavior
bool DirtyEsp()
{
	TEB * teb = NtCurrentTeb();

	CONTEXT lpContext;
	lpContext.ContextFlags = CONTEXT_CONTROL;
	if (GetThreadContext(GetCurrentThread(), &lpContext))
	{
		if (lpContext.Esp < (DWORD_PTR)teb->NtTib.StackLimit || lpContext.Esp >= (DWORD_PTR)teb->NtTib.StackBase)
		{
			return true;
		}
	}
	return false;

}

// Function calls should come from actual call instructions
// disasm call trace
// http://stackoverflow.com/questions/15650528/does-stackwalk64-work-on-64-bit-windows
// http://jpassing.com/2008/03/12/walking-the-stack-of-the-current-thread/

bool ROPTrace()
{
	EnterCriticalSection(&cs);
	CONTEXT lpContext;
	STACKFRAME64 stack_frame;
	memset(&stack_frame, 0, sizeof(stack_frame));
	memset(&lpContext, 0, sizeof(lpContext));

	lpContext.ContextFlags = CONTEXT_CONTROL;
	#if defined(_WIN64)
		RtlCaptureContext(&lpContext);

	#else
		__asm
		{
		Label:
			mov[lpContext.Ebp], ebp;
			mov[lpContext.Esp], esp;
			mov eax, [Label];
			mov[lpContext.Eip], eax;
		}
	#endif

	stack_frame.AddrPC.Mode         = AddrModeFlat;
	stack_frame.AddrStack.Mode      = AddrModeFlat;
	stack_frame.AddrFrame.Mode      = AddrModeFlat;
	#if defined(_WIN64)
		int machine_type = IMAGE_FILE_MACHINE_AMD64;
		stack_frame.AddrPC.Offset = lpContext.Rip;
		stack_frame.AddrFrame.Offset = lpContext.Rbp;
		stack_frame.AddrStack.Offset = lpContext.Rsp;
		stack_frame.AddrPC.Offset       = 0;
		stack_frame.AddrStack.Offset = 0;
		stack_frame.AddrFrame.Offset = 0;
	#else
		int machine_type = IMAGE_FILE_MACHINE_I386;
		stack_frame.AddrPC.Offset = lpContext.Eip;
		stack_frame.AddrFrame.Offset = lpContext.Ebp;
		stack_frame.AddrStack.Offset = lpContext.Esp;
	#endif

	int depth = 5;
	while (StackWalk64(machine_type, GetCurrentProcess(), GetCurrentThread(), &stack_frame, &lpContext, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
	{
		if (depth <= 0)
			break;

		//DWORD64 fp = stack_frame.AddrFrame.Offset;
		//fp += 4;

		if (stack_frame.AddrReturn.Offset == 0)
		{
			// this is expected for the last entry
			break;
		}
		if (stack_frame.AddrFrame.Offset == 0 || stack_frame.AddrPC.Offset == 0)
		{
			// sanity check
			break;
		}

		DWORD_PTR ra = stack_frame.AddrReturn.Offset;

		ra -= 6;
		if (!IsBadReadPtr((void*)ra, 6))
		{
			char * ptr = (char*)ra;

			/*AddrPC is the address of the call instruction, AddrReturn is the return address, the address of the previous call instruction (+5). Not sure what "stack 0" might mean. */

			// Standard call - 0xE8 (minus 5 bytes from returnAddr)
			// DWORD PTR call - 0xFF 0x15 (minus 6 bytes from returnAddr) .... example FF 15 <04 16 59 77>    call        dword ptr ds:[77591604h] 
			// Call esi FF D6
			// call ebx FF d3
			if (!((ptr[0] == '\xFF' && ptr[1] == '\x15') || (ptr[1] == '\xe8') || (ptr[4] == '\xff' && ptr[5] == '\xd6') || (ptr[4] == '\xff' && ptr[5] == '\xd3') ))
			{
				/*__asm
				{
					__emit 0xCC
				}*/
				LOG("S", "asm", ptr, 10);
				LeaveCriticalSection(&cs);

				return true;
			}

			//Todo: 64bit

		}


		depth--;

	}
	
	LeaveCriticalSection(&cs);

	return false;
}
bool HandleToProcessPath(HANDLE hProc, char * exePath)
{
	DWORD len = MAX_PATH;

	if (GetModuleFileNameExA(hProc, 0, exePath, MAX_PATH))
	{
		return true;
	}
	else
	{
		strcpy_s(exePath, MAX_PATH, "<Unknown>");
		return false;
	}

}

#ifdef _WIN64
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY              InMemoryOrderLinks;
	PVOID					Unk1;
	PVOID					Unk2;
	PVOID                   DllBase;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#else
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY              InMemoryOrderLinks;
	PVOID                   DllBase;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
#endif

/*__declspec(naked)
void*  firstLdrDataEntry() {
__asm {
mov eax, fs:[0x30]  // PEB
mov eax, [eax + 0x0C] // PEB_LDR_DATA
mov eax, [eax + 0x1C] // InInitializationOrderModuleList
retn
}
}
*/
//extern "C" PVOID firstLdrDataEntry();

// aleternate technique - https://www.honeynet.org/node/571

bool AddrOutsideModule2(DWORD_PTR Addr)
{

	MEMORY_BASIC_INFORMATION lpBuffer;
	memset(&lpBuffer, '\0', sizeof(MEMORY_BASIC_INFORMATION));
	VirtualQuery((void*)Addr, &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION));
	if (lpBuffer.Type == MEM_IMAGE)
		return false;
	else
		return true;

}

// This causes some recursion issues to NtAllocateVirtualMemory/NtCreateSection
bool AddressOutsideModule(DWORD_PTR Addr)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	// Take a snapshot of all modules in the specified process.
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	// Set the size of the structure before using it.
	me32.dwSize = sizeof(MODULEENTRY32);

	// Retrieve information about the first module,
	// and exit if unsuccessful
	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);           // clean the snapshot object
		return false;
	}

	// Now walk the module list of the process,
	do
	{
		if (((DWORD_PTR)me32.modBaseAddr <= Addr) && ((DWORD_PTR)me32.modBaseAddr + me32.modBaseSize >= Addr))
		{
			CloseHandle(hModuleSnap);
			return false;
		}

	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);


	return true;


}

NTSTATUS(WINAPI * OldNtProtectVirtualMemory)
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
    )
{
	try
	{
	
		PVOID Base = *BaseAddress;
		ULONG Size = *NumberOfBytesToProtect;

		bool drop = true;

		NTSTATUS retVal = OldNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
		if (retVal == STATUS_SUCCESS)
		{
			if ((NewAccessProtection & PAGE_EXECUTE_READ || NewAccessProtection & PAGE_EXECUTE_READWRITE) && Size != 37)
			{
				/* Possibly do these checks before the Old_ call to detect the method mcafee blogged about */
				if (DirtyEsp())
					LOG("s", "ROP_Detection", "STATUS_STACK_BUFFER_OVERRUN");

				if (NewAccessProtection & PAGE_EXECUTE_READWRITE)
				{
					if (ROPTrace())
                        LOG("sp", "ROP_Detection", "CALLER_CHECK", "Base", Base);
				}

				if (AddrOutsideModule2((DWORD_PTR)Base))
				{	
					// determine what memory this will actually modify
					MEMORY_BASIC_INFORMATION lpBuffer;
					memset(&lpBuffer, '\0', sizeof(MEMORY_BASIC_INFORMATION));
					VirtualQuery(Base, &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION));
                    LOG("llllllS", "AccessProtection", NewAccessProtection, "Size", Size, "BaseAddress", Base, "QueryBase", lpBuffer.BaseAddress, "RegionSize", lpBuffer.RegionSize, "AllocationBase", lpBuffer.AllocationBase, "Buffer", Base, 10);

					if (drop)
					{
						char outFile[MAX_PATH];
						sprintf_s(outFile, MAX_PATH, "C:\\drop\\%s_PVM_%x", "g_baseExe", lpBuffer.BaseAddress);
						HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
						if (hFile != INVALID_HANDLE_VALUE)
						{
							DWORD dWritten = 0;
							WriteFile(hFile, lpBuffer.BaseAddress, lpBuffer.RegionSize, &dWritten, 0);
							CloseHandle(hFile);
							drop = false;
						}
					}
					
				}
			}
		}
		return retVal;
	}
	catch (...)
	{
        LOG("s", "Exception", "NtProtectVirtualMemory");
		return -1;
	}
}



NTSTATUS(WINAPI * OldNtFreeVirtualMemory)
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
    )
{
    NTSTATUS retVal;

    try
    {
        // Useful to dump certain packed executables

        MEMORY_BASIC_INFORMATION lpBuffer;
        PVOID Base = *BaseAddress;
        char * charPtr = (char*)Base;
        SIZE_T Size = *RegionSize;
        VirtualQuery(Base, &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION));
        if (lpBuffer.State & MEM_COMMIT && !(lpBuffer.Type & MEM_IMAGE) && charPtr[0] == 'M' && charPtr[1] == 'Z' && charPtr[3] == '\0')
        {
            LOG("plplpS", "ProcessHandle", ProcessHandle, "Size", Size, "BaseAddress", Base, "RegionSize", lpBuffer.RegionSize, "RegionBase", lpBuffer.BaseAddress, "Buffer", Base, 10);

            char outFile[MAX_PATH];
            sprintf_s(outFile, MAX_PATH, "C:\\drop\\%s_FVM_MZ_%x", L"base", lpBuffer.BaseAddress);
            HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
            if (hFile != INVALID_HANDLE_VALUE)
            {
                DWORD dWritten = 0;
                WriteFile(hFile, lpBuffer.BaseAddress, lpBuffer.RegionSize, &dWritten, 0);
                CloseHandle(hFile);
            }
        }
    }
    catch (...)
    {

    }

    retVal = OldNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);

    return retVal;

}
