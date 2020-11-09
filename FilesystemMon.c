/*
Monitoring Driver
Author: Emanuel Durmaz
*/

/*++

Module Name:

    FilesystemMonitoring.c

Abstract:

    This is the main module of the FilesystemMonitoring miniFilter driver.

Environment:

    Kernel mode

--*/

#include "WPP.h"
#include "FilesystemMon.h" 
#include "FilesystemMon.tmh" 

#define RUN_WPP

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{ IRP_MJ_CREATE,0,PreOperation,NULL }, // register a PreOperation callback for Create / Open. PostOperation not needed.
	{ IRP_MJ_READ,0,PreOperation,NULL },
	{ IRP_MJ_WRITE,0,PreOperation,NULL },
	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,0,PreOperation,NULL},
	{ IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks, //register our callbacks
	DriverUnload, //register unload function
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	WPP_SYSTEMCONTROL(driverObject); 
	WPP_INIT_TRACING(driverObject, registryPath);
	g_DriverObject = driverObject;

	Log("DriverEntry FilesystemMonitoring");	
	// use .reload in windbg terminal to load symbols for first debug run

	//We need this function later
	if (NULL == ZwQueryInformationProcess)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
		ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess)
		{
			Log("Cannot resolve ZwQueryInformationProcess");
			return STATUS_NOT_FOUND;
		}
	}

	//register to the filter manager
	NTSTATUS status = FltRegisterFilter(driverObject, &FilterRegistration, &FilterHandle);

	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(FilterHandle);
		//if filtering doesnt start, unregister our filter
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(FilterHandle);
			return status;
		}
	}

	//register a callback to get a notifcation about process termination (and creation)
	status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ProcessNotifyRoutine, FALSE);

	if (!NT_SUCCESS(status))
		FltUnregisterFilter(FilterHandle);

	return status;
}

NTSTATUS DriverUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
	UNREFERENCED_PARAMETER(flags);
	Log("DriverUnload");

	//unregister filter / callbacks
	FltUnregisterFilter(FilterHandle);
	NTSTATUS status = PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ProcessNotifyRoutine, TRUE);

	WPP_CLEANUP(g_DriverObject);
	return status;
}


FLT_PREOP_CALLBACK_STATUS PreOperation(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* completionContext)
{
	UNREFERENCED_PARAMETER(fltObjects);
	UNREFERENCED_PARAMETER(completionContext);
	UNREFERENCED_PARAMETER(data);

	WCHAR filePath[MAXIMUM_FILENAME_LENGTH] = { 0 };
	ExtractFilePath(data, filePath);

	//DbgBreakPoint();
	ULONG processId = FltGetRequestorProcessId(data);
	PEPROCESS pProcess = FltGetRequestorProcess(data);
	if (pProcess != NULL)
	{
		WCHAR imagePath[MAXIMUM_FILENAME_LENGTH] = { 0 };
		GetProcessImagePath(pProcess, imagePath);

		SIZE_T len = wcslen(filePath);
		if (len > 0)
		{
			if (data->Iopb->MajorFunction == IRP_MJ_CREATE)
				Log("IRP_MJ_CREATE: processId: %lu | procImagePath: %ws | filePath: %ls", processId, imagePath, filePath);
			else if (data->Iopb->MajorFunction == IRP_MJ_READ)
				Log("IRP_MJ_READ: processId: %lu | procImagePath: %ws | filePath: %ls", processId, imagePath, filePath);
			else if (data->Iopb->MajorFunction == IRP_MJ_WRITE)
				Log("IRP_MJ_WRITE: processId: %lu | procImagePath: %ws | filePath: %ls", processId, imagePath, filePath);
			else if (data->Iopb->MajorFunction == IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION)
				Log("IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: processId: %lu | procImagePath: %ws | filePath: %ls", processId, imagePath, filePath);
		}
			
	}

	/*
	The minifilter driver is returning the I/O operation to the filter manager for further processing.
	In this case, the filter manager does not call the minifilter driver's post-operation callback, if one exists, during I/O completion.
	*/
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

VOID ProcessNotifyRoutine(HANDLE hParentId, HANDLE hProcessId, BOOLEAN isCreateProcess) //hProcessId is really the process id
{
	UNREFERENCED_PARAMETER(hParentId);

	ULONG parentProcId = HandleToUlong(hParentId);
	ULONG procId = HandleToUlong(hProcessId);

	PEPROCESS pProcess;
	NTSTATUS status = PsLookupProcessByProcessId(hProcessId, &pProcess);

	WCHAR procImagePath[MAXIMUM_FILENAME_LENGTH] = { 0 };
	GetProcessImagePath(pProcess, procImagePath);

	status = PsLookupProcessByProcessId(hParentId, &pProcess);
	WCHAR parentImagePath[MAXIMUM_FILENAME_LENGTH] = { 0 };
	GetProcessImagePath(pProcess, parentImagePath);

	if (isCreateProcess)
		Log("CREATE PROCESS: procId: %lu | procImagePath: %ws | parentProcId: %lu | parentImagePath: %ws", procId, procImagePath, parentProcId, parentImagePath);
	else
		Log("TERMINATE PROCESS: procId: %lu | procImagePath: %ws | parentProcId: %lu | parentImagePath: %ws", procId, procImagePath, parentProcId, parentImagePath);


	ObDereferenceObjectDeferDelete(pProcess);
}