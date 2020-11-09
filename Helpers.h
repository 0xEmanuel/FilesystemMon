#pragma once

#include "Utils.h"
#include <bcrypt.h>

//constants
#define BUFFERSIZE_READFILE_OPERATION 4096

//Monitor allocations and deallocations with: ./poolmon -iwz*

//use one tag per allocation
#define HASH_OBJECT_TAG 'OHzw' //Tag would appear as "wzHO" in the pool dump
#define HASH_DATA_TAG 'DHzw' // Tag: wzHD

//typedefs
typedef NTSTATUS(*QUERY_INFO_PROCESS)
(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

//declarations
QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS GetProcessImagePath(PEPROCESS pProcess, OUT PWCHAR imagePath);
NTSTATUS ExtractFilePath(IN PFLT_CALLBACK_DATA data, OUT PWCHAR filename);
NTSTATUS CalcHash(IN LPCWSTR hashAlgorithmId, IN PCWSTR filePath, IN DWORD buffersize, OUT PCHAR hexStrBuf);

VOID PrintObjectInformationsByHandle(HANDLE hObject);