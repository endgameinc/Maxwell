#include <Windows.h>

#include "log.h"
#include "hook.h"
#include "whitelist.h"
#include "MemGuard.h"

#pragma comment(lib, "Ws2_32.lib")

CRITICAL_SECTION cs;

extern LONG CALLBACK VectoredHandler(
    _In_ PEXCEPTION_POINTERS ExceptionInfo
    );

static Hook Hooks[] =
{
    /*File*/
    {L"ntdll.dll", "NtWriteFile", MyNtWriteFile, (void**)&OldNtWriteFile},
    {L"ntdll.dll", "NtCreateFile", MyNtCreateFile, (void**)&OldNtCreateFile},
    {L"ntdll.dll", "NtQueryAttributesFile", MyNtQueryAttributesFile, (void**)&OldNtQueryAttributesFile},

    /*Registry*/
    {L"ntdll.dll", "NtSetValueKey", MyNtSetValueKey, (void**)&OldNtSetValueKey},
    {L"ntdll.dll", "NtOpenKeyEx", MyNtOpenKeyEx, (void**)&OldNtOpenKeyEx},

    /*Process*/
    {L"ntdll.dll", "NtCreateUserProcess", MyNtCreateUserProcess, (void**)&OldNtCreateUserProcess},
    {L"ntdll.dll", "NtCreateProcess", MyNtCreateProcess, (void**)&OldNtCreateProcess},
    {L"ntdll.dll", "NtCreateProcessEx", MyNtCreateProcessEx, (void**)&OldNtCreateProcessEx},
	
    /*Misc*/
    {L"ntdll.dll", "NtDelayExecution", MyNtDelayExecution, (void**)&OldNtDelayExecution},
    {L"ntdll.dll", "NtFreeVirtualMemory", MyNtFreeVirtualMemory, (void**)&OldNtFreeVirtualMemory},

};


void FluxMain()
{
    if (ProcessWhitelist())
        return;

    HANDLE hThread = INVALID_HANDLE_VALUE;
    //hThread = CreateThread(0, 0, WorkThread, 0, 0, 0);

    DWORD retVal = MaxLog::InitLog();
    if (retVal)
    {
        //printf("InitLog error: %d\n", retVal);
    }
    
    if (strcmp(MaxLog::g_baseExe, "WerFault.exe") == 0)
    {
        LOG("s", "WerFault", "Application Crash"); 
    }

    if (hThread != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hThread);
    }

    InitializeCriticalSection(&cs);

    for (int i = 0; i < ARRAYSIZE(Hooks); i++)
    {
        InstallHook(&Hooks[i]);
    }

    InitEAF();
}

BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        FluxMain();
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    }
    return true;
}