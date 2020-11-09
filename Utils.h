#pragma once

#include <fltKernel.h>

#include <stdarg.h>
#include <Ntstrsafe.h>
#include <strsafe.h>


#define LOG_MSG_BUFSIZE 4096
#define ENABLE_WPP_TRACING TRUE
#define ENABLE_DBGPRINT TRUE

#if defined(WALLETPROTECTION)
	#define PREFIX "WalletProtectionMiniFilter: "
#else
	#define PREFIX "DBG_DEFAULT: "
#endif

VOID __cdecl Log(_In_z_ _Printf_format_string_ PCSTR format, ...);
ULONG vLog(_In_z_ _Printf_format_string_ PCSTR format, va_list arglist);


INT FindStringInArrayA(CHAR* findStr, CONST CHAR * strArray[], DWORD length);
INT FindStringInArrayW(WCHAR* findStr, CONST WCHAR * strArray[], DWORD length);

VOID PrintArray(ULONG intArr[], DWORD length);

VOID ExtractFilenameW(IN WCHAR* filePath, OUT WCHAR* fileNameBuffer, IN DWORD bufferSize);

NTSTATUS BytesToHexString(IN PUCHAR bytes, IN DWORD byteCount, IN SIZE_T hexStrSize, IN SIZE_T hexStrBufSize, OUT PCHAR hexStrBuf);