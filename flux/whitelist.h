#ifndef _WHITELIST_H_
#define _WHITELIST_H_
bool ProcessWhitelist();
bool IsFilePathWhitelisted(const wchar_t * filePath, size_t len);

#endif