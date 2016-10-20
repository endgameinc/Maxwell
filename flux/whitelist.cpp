#include <Windows.h>
#include "log.h"

const char *process_whitelist[] = {
	"C:\\Python27\\python.exe",
	"\\\\?\\C:\\Windows\\system32\\wbem\\WMIADAP.EXE",
    "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\mscorsvw.exe",
};

bool ProcessWhitelist()
{
	char ProcPath[MAX_PATH];
	GetModuleFileNameA(NULL, ProcPath, MAX_PATH);
	for (int i = 0; i < ARRAYSIZE(process_whitelist); i++)
	{
        if (strcmp(ProcPath, process_whitelist[i]) == 0)
        {
            return true;
        }
	}
	return false;

}

typedef struct
{
    const wchar_t * filePath;
    int             ruleType;
} FileWhitelist;

const FileWhitelist fileWhitelist[] =
{
	{L"\\lsass", 0},
	{L"\\wkssvc", 0},
	{L"\\MsFteWds", 0},
	{L"\\srvsvc", 0},
    {L"\\Maxwell", 0},
    {L"\\traffic.pcap", 0},
    {L"\\Users\\max\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\Content.IE5\\", 1},
    {L"\\Users\\max\\AppData\\Roaming\\Microsoft\\Windows\\Cookies\\", 1},
    {L"\\Users\\max\\AppData\\Local\\Microsoft\\Internet Explorer\\DOMStore\\", 1},
    {L"\\Users\\max\\AppData\\Local\\Microsoft\\Internet Explorer\\Recovery", 1},
    {L"\\Users\\max\\AppData\\LocalLow\\Microsoft\\Internet Explorer\\Services\\", 1},
    {L"\\Users\\max\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\", 1},
    {L"\\Users\\max\\AppData\\Roaming\\Macromedia\\Flash Player\\", 1},
    {L"\\Users\\max\\AppData\\Roaming\\Adobe\\Flash Player\\AssetCache\\", 1},
    {L"\\Users\\max\\AppData\\Roaming\\Microsoft\\Internet Explorer\\UserData\\", 1},
    {L"\\Users\\max\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportArchive\\NonCritical", 1},
	{L"\\Windows\\System32\\wbem\\Performance\\", 1},
	{L"\\Windows\\Microsoft.NET\\Framework\v2.0.50727\\", 1},
    {L"\\Users\\max\\AppData\\Local\\Microsoft\\Internet Explorer\\VersionManager\\ver", 1},
	{L"\\logs\\", 1},
	{L"\\drop\\", 1},
};

bool IsFilePathWhitelisted(const wchar_t * filePath, size_t len)
{
    for (size_t i = 0; i < ARRAYSIZE(fileWhitelist); i++)
    {
        if (fileWhitelist[i].ruleType == 0)
        {
            if (memcmp(filePath, fileWhitelist[i].filePath, sizeof(fileWhitelist[i].filePath)) == 0)
            {
                return true;
            }
        }
        else if (_wcsnicmp(filePath, fileWhitelist[i].filePath, sizeof(fileWhitelist[i].filePath)) == 0)
        {
            return true;
        }

    }
    return false;
}
