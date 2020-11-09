#pragma once

#include "Utils.h"
#include "Helpers.h"

//#include "../WalletProtectionMiniFilter/WalletProtectionMiniFilter/Helpers.h"

PFLT_FILTER FilterHandle = NULL;
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS flags);
FLT_PREOP_CALLBACK_STATUS PreOperation(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* completionContext);

VOID ProcessNotifyRoutine(HANDLE hParentId, HANDLE hProcessId, BOOLEAN isCreateProcess);

PDRIVER_OBJECT g_DriverObject = NULL;