#include "WPP.h"
#include "Utils.h"
#include "Utils.tmh" 

VOID __cdecl Log(_In_z_ _Printf_format_string_ PCSTR format, ...)
{
	va_list arglist;
	
	if (ENABLE_DBGPRINT)
	{
		va_start(arglist, format);
		
		vDbgPrintExWithPrefix(PREFIX,DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, format, arglist);
		va_end(arglist);
	}

	if (ENABLE_WPP_TRACING)
	{
		CHAR logmsg[LOG_MSG_BUFSIZE] = {0};
		va_start(arglist, format);
		vsprintf(logmsg, format, arglist);
		va_end(arglist);

		DoTraceMessage(FLAG_ONE, "%s", logmsg); // ignore 'indentifier ... undefined'
	}
}

ULONG vLog(_In_z_ _Printf_format_string_ PCSTR format, va_list arglist)
{
	CHAR prefixFormat[LOG_MSG_BUFSIZE] = { 0 };
	NTSTATUS status = StringCchCopyA(prefixFormat, LOG_MSG_BUFSIZE, PREFIX); //prefix
	status = RtlStringCchCatA((NTSTRSAFE_PSTR)prefixFormat, LOG_MSG_BUFSIZE, format);

	CHAR formatBuf[LOG_MSG_BUFSIZE] = { 0 };
	status = StringCchCopyA(formatBuf, LOG_MSG_BUFSIZE, prefixFormat);
	status = RtlStringCchCatA((NTSTRSAFE_PSTR)formatBuf, LOG_MSG_BUFSIZE, "\r\n"); //suffix

	return vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, formatBuf, arglist);
}


INT FindStringInArrayA(CHAR* findStr, CONST CHAR * strArray[], DWORD length)
{
	for (DWORD i = 0; i < length; i++)
		if (strcmp(findStr, strArray[i]) == 0)
			return i;
	return -1;
}

INT FindStringInArrayW(WCHAR* findStr, CONST WCHAR * strArray[], DWORD length)
{
	for (DWORD i = 0; i < length; i++)
		if (wcscmp(findStr, strArray[i]) == 0)
			return i;
	return -1;
}

VOID PrintArray(ULONG intArr[], DWORD length)
{
	for (DWORD i = 0; i < length; i++)
		Log("[%d] = %lu", i, intArr[i]); // Log prints always newline
}

VOID ExtractFilenameW(IN WCHAR* filePath, OUT WCHAR* fileNameBuffer, IN DWORD bufferSize)
{
	WCHAR* lastMatch = NULL;
	for (DWORD i = 0; filePath[i] != (WCHAR)('\0'); i++) //filePath has to be NUL terminated
		if (filePath[i] == (WCHAR)('\\'))
			lastMatch = &filePath[i]; //take pointer to this backslash occurrence

	if (lastMatch == NULL) //found no backslash
		return;

	WCHAR* filename = lastMatch + 1; //skip first character which is backslash
	RtlCopyMemory(fileNameBuffer, filename, bufferSize);
}

NTSTATUS BytesToHexString(IN PUCHAR bytes, IN DWORD byteCount, IN SIZE_T hexStrSize, IN SIZE_T hexStrBufSize, OUT PCHAR hexStrBuf)
{
	NTSTATUS status = STATUS_SUCCESS;
	//convert byte stream to hex string

	//hexStrSize is the actual size of the hexstring that is going to be created. in case of SHA256 (32 Bytes) -> bytes = 32 -> 64 HexDigits + NUL terminator = 65 bytes to allocate
	//hexStrBufSize is the buffersize and thus the maximum allowed string length.

	if (hexStrSize > hexStrBufSize)
	{
		status = STATUS_BUFFER_TOO_SMALL;
		return status;
	}

	CHAR tmpBuf[3] = { 0 }; // temporary logmsg to hold 2 HexDigits + NUL terminator
	for (DWORD i = 0; i < byteCount; i++)
	{
		UCHAR byte = *(bytes + i);
		status = RtlStringCchPrintfA(tmpBuf, sizeof(tmpBuf), "%02x", byte); //save hashByte as hexstring with padding
		if (!NT_SUCCESS(status))
			break;

		status = RtlStringCchCatA((NTSTRSAFE_PSTR)hexStrBuf, hexStrSize, tmpBuf); //concat hexstrings to one string
		if (!NT_SUCCESS(status))
			break;
	}

	return status;
}