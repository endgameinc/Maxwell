#ifndef __EAF_H__
#define __EAF_H__
#include <Windows.h>
#include <TlHelp32.h>

LONG CALLBACK VectoredHandler(
	_In_ PEXCEPTION_POINTERS ExceptionInfo
	);

void InitEAF();
bool AddressToModule(DWORD_PTR Addr, wchar_t * modName, unsigned int size);


extern void * guardList[20];
extern int gCount;

#endif
