#include "log.h"

namespace MaxLog
{
static CRITICAL_SECTION g_cs;
static DWORD g_pid, g_ppid;
static char g_modBuf[MAX_PATH];
static HANDLE g_hPipe;
const char *g_baseExe;
_NtQueryVirtualMemory g_NtQueryVirtualMemory = 0;
_NtQueryInformationThread g_NtQueryInformationThread = 0;

DWORD InitLog()
{
    DWORD retVal = 0;
    DWORD pipeMode = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    g_hPipe = INVALID_HANDLE_VALUE;

    InitializeCriticalSection(&g_cs);
    GetModuleFileNameA(NULL, g_modBuf, ARRAYSIZE(g_modBuf));

    g_NtQueryVirtualMemory = (_NtQueryVirtualMemory)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryVirtualMemory");
    g_NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryInformationThread");

    // extract only the filename of the process, not the entire path
    for (const char *p = g_baseExe = g_modBuf; *p != 0; p++)
    {
        if (*p == '\\' || *p == '/')
        {
            g_baseExe = p + 1;
        }
    }

    g_pid = GetCurrentProcessId();

    g_hPipe = CreateFile(MAXWELL_PIPE_NAME, GENERIC_WRITE, FILE_SHARE_WRITE,
        0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, 0);

    if (INVALID_HANDLE_VALUE == g_hPipe)
    {
        return GetLastError();
    }

    if (!SetNamedPipeHandleState(g_hPipe, &pipeMode, 0, 0))
    {
        return GetLastError();
    }

    return 0;

}

char * USC2toUTF8(LPCWSTR pUSC2, int nUSC2)
{
    // Get the size for our buffer
    int outLen = WideCharToMultiByte(CP_UTF8, 0, pUSC2, nUSC2, 0, 0, 0, 0);

    // Extra byte to ensure this will be null terminated
    char * pUTF8 = (char*)malloc(outLen + 1);
    pUTF8[outLen] = 0;
    WideCharToMultiByte(CP_UTF8, 0, pUSC2, nUSC2, (LPSTR)pUTF8, outLen, 0, 0);

    return pUTF8;
}

wchar_t * UTF8toUSC2(char * pUTF8, int nUTF8)
{
    // Get the size for our buffer
    int outLen = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)pUTF8, nUTF8, 0, 0);

    // Extra byte to ensure this will be null terminated
    wchar_t * pUSC2 = (wchar_t*)malloc(outLen + 1);
    pUSC2[outLen] = L'\0';
    MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)pUTF8, nUTF8, pUSC2, outLen);

    return pUSC2;

}

void pack_str(msgpack_packer * pk, const char * sVal)
{
    msgpack_pack_str(pk, strlen(sVal));
    msgpack_pack_str_body(pk, sVal, strlen(sVal));
}

void pack_str_n(msgpack_packer * pk, const char * sVal, size_t len)
{
    msgpack_pack_str(pk, len);
    msgpack_pack_str_body(pk, sVal, len);
}

void pack_wstr(msgpack_packer * pk, const wchar_t * wVal)
{
    char * sVal = USC2toUTF8(wVal, wcslen(wVal));
    msgpack_pack_str(pk, strlen(sVal));
    msgpack_pack_str_body(pk, sVal, strlen(sVal));
    free(sVal);
}

void pack_wstr_n(msgpack_packer * pk, const wchar_t * wVal, size_t len)
{
    char * sVal = USC2toUTF8(wVal, len);
    msgpack_pack_str(pk, strlen(sVal));
    msgpack_pack_str_body(pk, sVal, strlen(sVal));

    free(sVal);
}

void pack_bin_n(msgpack_packer * pk, void * vVal, size_t len)
{
    msgpack_pack_bin(pk, len);
    msgpack_pack_bin_body(pk, vVal, len);
}

void pack_ptr(msgpack_packer * pk, DWORD_PTR val)
{
    char buf[20];
#ifdef _AMD64_
    sprintf_s(buf,20, "0x%016llX", val);
#else
    sprintf_s(buf,20, "0x%08lX", val);
#endif
    msgpack_pack_str(pk, strlen(buf));
    msgpack_pack_str_body(pk, buf, strlen(buf));

}

void pack_dword_x(msgpack_packer * pk, DWORD val)
{
    char buf[20];
    sprintf_s(buf, 20, "0x%08lX", val);
    msgpack_pack_str(pk, strlen(buf));
    msgpack_pack_str_body(pk, buf, strlen(buf));

}

void parseArgs(va_list args, const char * fmt, msgpack_packer *pk, ...)
{
    DWORD count = strlen(fmt);
    for (DWORD i = 0; i < count; i++)
    {
        char type = fmt[i];
        const char * key = va_arg(args, const char *);
        pack_str(pk, key);

        if (type == 's')
        {
            const char * val = va_arg(args, const char *);
            pack_str(pk, val);
        }
        else if (type == 'S')
        {
            const char * val = va_arg(args, const char *);
            size_t len = va_arg(args, size_t);
            pack_str_n(pk, val, len);
        }
        else if (type == 'u')
        {
            const wchar_t * val = va_arg(args, const wchar_t *);
            pack_wstr(pk, val);
        }
        else if (type == 'U')
        {
            const wchar_t * val = va_arg(args, const wchar_t *);
            size_t len = va_arg(args, size_t);
            pack_wstr_n(pk, val, len);
        }
        else if (type == 'i')
        {
            unsigned long val = va_arg(args, int);
            msgpack_pack_int32(pk, val);
        }
        else if (type == 'l')
        {
            unsigned long val = va_arg(args, unsigned long);
            msgpack_pack_unsigned_long(pk, val);
        }
        else if (type == 'q')
        {
            unsigned long long val = va_arg(args, unsigned long long);
            msgpack_pack_uint64(pk, val);
        }
        else if (type == 'o')
        {
            UNICODE_STRING* val = va_arg(args, UNICODE_STRING*);
            pack_wstr_n(pk, val->Buffer, val->Length / 2);
        }
        else if (type == 'x')
        {
            DWORD_PTR val = va_arg(args, DWORD);
            pack_dword_x(pk, val);
        }
        else if (type == 'p')
        {
            DWORD_PTR val = va_arg(args, DWORD_PTR);
            pack_ptr(pk, val);
        }
        else if (type == 'b')
        {
            void * val = va_arg(args, void*);
            size_t len = va_arg(args, size_t);
            pack_bin_n(pk, val, len);
        }
        else
        {
            printf("Invalid format specifier\n");
            msgpack_pack_str(pk, 3);
            msgpack_pack_str_body(pk, "err", 3);
        }

    }


}

void Log(const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    msgpack_sbuffer sbuf; /* buffer */
    msgpack_packer pk;    /* packer */
    DWORD count = strlen(fmt);
    DWORD bytesWritten = 0;
    BOOL retVal;

    msgpack_sbuffer_init(&sbuf); /* initialize buffer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    msgpack_pack_map(&pk, count + 1);

    pack_str(&pk, "plugin");
    pack_str(&pk, MAXWELL_PLUGIN_NAME);



    parseArgs(args, fmt, &pk);

    EnterCriticalSection(&g_cs);

    retVal = WriteFile(g_hPipe, sbuf.data, sbuf.size, &bytesWritten, 0);
    if (!retVal)
    {
        int lasterr = GetLastError();
        if (ERROR_NO_DATA == lasterr)
        {
            // Pipe was closed on the other end, reconnect
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
            if (0 == InitLog())
            {
                // Connected succesfully, try to resend
                (void)WriteFile(g_hPipe, sbuf.data, sbuf.size, &bytesWritten, 0);
            }
        }
        else if (ERROR_INVALID_HANDLE == lasterr)
        {
            // We are not currently connected, attempt to connect
            if (0 == InitLog())
            {
                // Connected succesfully, try to resend
                (void)WriteFile(g_hPipe, sbuf.data, sbuf.size, &bytesWritten, 0);
            }
        }
        else
        {
            printf("lasterr: %d\n", lasterr);
        }
    }

    LeaveCriticalSection(&g_cs);

    msgpack_sbuffer_destroy(&sbuf);

    return;

}

void LogWithMeta(const char * fmt, ...)
{
    DWORD bytesWritten = 0;
    va_list args;
    va_start(args, fmt);
    msgpack_sbuffer sbuf; /* buffer */
    msgpack_packer pk;    /* packer */
    DWORD count = 0;
    BOOL retVal;
    wchar_t threatStartModule[MAX_PATH];
    ModuleThread(threatStartModule);

    count = strlen(fmt);

    const char *functionName = va_arg(args, const char *);

    msgpack_sbuffer_init(&sbuf); /* initialize buffer */
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write); /* initialize packer */

    msgpack_pack_map(&pk, count + 5);

    pack_str(&pk, "plugin");
    pack_str(&pk, MAXWELL_PLUGIN_NAME);

    pack_str(&pk, "pid");
    msgpack_pack_uint32(&pk, g_pid);

    pack_str(&pk, "process");
    pack_str(&pk, g_modBuf);

    pack_str(&pk, "threatStartModule");
    pack_wstr(&pk, threatStartModule);

    pack_str(&pk, "function");
    pack_str(&pk, functionName);

    parseArgs(args, fmt, &pk);

    EnterCriticalSection(&g_cs);

    retVal = WriteFile(g_hPipe, sbuf.data, sbuf.size, &bytesWritten, 0);
    if (!retVal)
    {
        int lasterr = GetLastError();
        if (ERROR_NO_DATA == lasterr)
        {
            // Pipe was closed on the other end, reconnect
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
            if (0 == InitLog())
            {
                // Connected succesfully, try to resend
                (void)WriteFile(g_hPipe, sbuf.data, sbuf.size, &bytesWritten, 0);
            }
        }
        else if (ERROR_INVALID_HANDLE == lasterr)
        {
            // We are not currently connected, attempt to connect
            if (0 == InitLog())
            {
                // Connected succesfully, try to resend
                (void)WriteFile(g_hPipe, sbuf.data, sbuf.size, &bytesWritten, 0);
            }
        }
        else
        {
            printf("lasterr: %d\n", lasterr);
        }
    }

    LeaveCriticalSection(&g_cs);

    msgpack_sbuffer_destroy(&sbuf);

    return;
}

void ModuleThread(wchar_t * module)
{
   
    // This leads to a heap alloc, we don't want that for performance
    // swprintf_s(module, MAX_PATH, L"%ws", L"<Unknown>");
    memcpy(module, L"<Unknown>",20);

    if (!g_NtQueryInformationThread)
    {
        return;
    }

    DWORD_PTR startAddress = 0;
    ULONG retSize = 0;

    if (g_NtQueryInformationThread(GetCurrentThread(), 9, &startAddress, sizeof(PVOID), &retSize) == STATUS_SUCCESS)
    {
        AddressToModule(startAddress, module, MAX_PATH);
    }

    return;

}

bool AddressToModule(DWORD_PTR Addr, wchar_t * modName, unsigned int size)
{
    NTSTATUS ntStatus = 0;
    SIZE_T outBufLen = 0;
    WCHAR stringBuffer[0x500];
    PUNICODE_STRING string = (PUNICODE_STRING)stringBuffer;
    string->Buffer = stringBuffer + 4;
    string->Length = 0x0;
    string->MaximumLength = 1000;

    memcpy(modName, L"<Unknown>", sizeof(L"<Unknown>"));

    if (!g_NtQueryVirtualMemory)
        return false;

    ntStatus = g_NtQueryVirtualMemory(GetCurrentProcess(), (void*)Addr, MemorySectionName, string, 528, &outBufLen);

    if (STATUS_SUCCESS == ntStatus)
    {
        wchar_t * mod = &string->Buffer[wcslen(string->Buffer)];
        while (*mod != L'\\')
        {
            mod--;
        }
        mod++;

        /*
        // For full path
        if (memcmp(string->Buffer, L"\\Device\\HarddiskVolume", 44) == 0)
        {
        swprintf_s(modName, size, L"%ws%ws", L"C:\\", &string->Buffer[24]);
        }
        */
        memcpy(modName, mod, (wcslen(mod) + 1) * 2);
        return true;

    }

    return false;
}


}