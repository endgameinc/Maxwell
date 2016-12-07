#include <Windows.h>
#include "distorm\distorm.h"
#include "hook.h"

#ifdef _WIN64
#pragma comment(lib,"distorm\\distorm64.lib")
#else
#pragma comment(lib,"distorm\\distorm32.lib")
#endif

#ifdef _WIN64
void InstallHook(Hook * hook)
{
    DWORD dwOld;
    LPVOID trampAddr = NULL;
    int trampSize = 0;

    // allocate tramp buffer
    trampAddr = VirtualAlloc(0, 37, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    unsigned __int64 trampAddrInt = (unsigned __int64)trampAddr;

    memset(trampAddr, '\x90', 37);

    // find target function
    PVOID targetFunc = (PVOID)GetProcAddress(GetModuleHandle(hook->libName), hook->functionName);

    if (targetFunc == 0)
        return;


    // distorm code
    // How many instructions to allocate on stack.
#define MAX_INSTRUCTIONS 32
    // Holds the result of the decoding.
    _DecodeResult res;
    // Default offset for buffer is 0.
    _OffsetType offset = 0;
    // Decoded instruction information - the Decode will write the results here.
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    // decodedInstructionsCount indicates how many instructions were written to the result array.
    unsigned int decodedInstructionsCount = 0;
    // Default decoding mode is 32 bits.
    _DecodeType dt = Decode64Bits;

    // Decode the buffer at given offset (virtual address).
    res = distorm_decode(offset, (const unsigned char*)targetFunc, 32, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    if (res == DECRES_INPUTERR)
        return;

    unsigned int totalSize = 0;

    for (unsigned int x = 0; x < decodedInstructionsCount; x++)
    {
        if (totalSize >= 12)
            break;
        totalSize += decodedInstructions[x].size;
    }
    // end distorm code
    log("Total size of tramp: %d", totalSize);
    trampSize = totalSize;


    hook->oldFunc = (void*)trampAddr;

    unsigned __int64 targetFuncInt = (unsigned __int64)targetFunc;

    //copy first x bytes of function to tramp
    memcpy(trampAddr, targetFunc, totalSize);
    //create a jump to original function+totalSize from tramp
    trampAddrInt += totalSize;
    memcpy((PVOID)trampAddrInt, "\x48\xb8", 2);
    trampAddrInt += 2;
    targetFuncInt += totalSize;
    memcpy((PVOID)trampAddrInt, &targetFuncInt, 8);
    trampAddrInt += 8;
    memcpy((PVOID)trampAddrInt, "\xff\xe0", 2);
    // trampoline has been constructed

    //reset pointer
    targetFuncInt = (unsigned __int64)targetFunc;

    //set target function writeable, should probably set its old permissions for stealth
    VirtualProtect((LPVOID)targetFunc, 37, PAGE_EXECUTE_READWRITE, &dwOld);

    //intercept target function, send all calls to my function
    unsigned __int64 myFuncInt = (unsigned __int64)hook->myFunc;
    memcpy((PVOID)targetFuncInt, "\x48\xb8", 2);
    targetFuncInt += 2;
    memcpy((PVOID)targetFuncInt, &myFuncInt, 8);
    targetFuncInt += 8;
    memcpy((PVOID)targetFuncInt, "\xff\xe0", 2);
    targetFuncInt += 2;

    // fix memory protection for hooked function
    VirtualProtect((LPVOID)targetFunc, 37, dwOld, &dwOld);

    // hooking is now complete

}
#else

void InstallHook(Hook * hook)
{
    DWORD dwOld;
    LPVOID trampAddr = NULL;
    int trampSize = 0;

    // allocate tramp buffer
    trampAddr = VirtualAlloc(0, 37, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (trampAddr == NULL)
        return;

    DWORD trampAddrPtr = (DWORD)trampAddr;

    memset(trampAddr, '\x90', 37);

    // find target function
    PVOID targetFunc = (PVOID)GetProcAddress(GetModuleHandle(hook->libName), hook->functionName);

    if (targetFunc == 0)
        return;

    // distorm code
    // How many instructions to allocate on stack.
#define MAX_INSTRUCTIONS 32
    // Holds the result of the decoding.
    _DecodeResult res;
    // Default offset for buffer is 0.
    _OffsetType offset = 0;
    // Decoded instruction information - the Decode will write the results here.
    _DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
    // decodedInstructionsCount indicates how many instructions were written to the result array.
    unsigned int decodedInstructionsCount = 0;
    // Default decoding mode is 32 bits.
    _DecodeType dt = Decode32Bits;

    // Decode the buffer at given offset (virtual address).
    res = distorm_decode(offset, (const unsigned char*)targetFunc, 32, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    if (res == DECRES_INPUTERR)
        return;

    unsigned int totalSize = 0;

    for (unsigned int x = 0; x < decodedInstructionsCount; x++)
    {
        if (totalSize >= 5)
            break;
        totalSize += decodedInstructions[x].size;
    }
    // end distorm code
    //log("Total size of tramp: %d", totalSize);

    trampSize = totalSize;

    *(hook->oldFunc) = trampAddr;

    DWORD targetFuncPtr = (DWORD)targetFunc;

    ULONG bytes = 20;
    //set target function writeable
    //if (strncmp(hook->funcName, "NtProtectVirtualMemory", sizeof("NtProtectVirtualMemory") -1) == 0)
    VirtualProtect((LPVOID)targetFunc, 37, PAGE_EXECUTE_READWRITE, &dwOld);
    //else
    //	Old_NtProtectVirtualMemory(GetCurrentProcess(), &targetFunc, &bytes, PAGE_EXECUTE_READWRITE, &dwOld);
    //copy instructions of function to tramp
    memcpy(trampAddr, targetFunc, totalSize);
    //create a jump to original function+5 from tramp
    trampAddrPtr += totalSize;
    memcpy((PVOID)trampAddrPtr, "\xe9", 1);
    // offset = destination - address of e9 - 5
    int myOffset = (int)targetFuncPtr + totalSize - (int)trampAddrPtr - 5;
    trampAddrPtr += 1;
    memcpy((PVOID)trampAddrPtr, &myOffset, 4);
    // trampoline has been constructed

    //reset pointer
    targetFuncPtr = (DWORD)targetFunc;

    //intercept target function, send all calls to my function
    DWORD myFuncPtr = (DWORD)hook->myFunc;
    memcpy((PVOID)targetFuncPtr, "\xe9", 1);
    // offset = destination - address of e9 - 5
    myOffset = (int)myFuncPtr - (int)targetFuncPtr - 5;
    targetFuncPtr += 1;
    memcpy((PVOID)targetFuncPtr, &myOffset, 4);

    // fix memory protection for hooked function
    VirtualProtect((LPVOID)targetFunc, 37, dwOld, &dwOld);

}

#endif




