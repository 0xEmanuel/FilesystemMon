#include "Helpers.h"

NTSTATUS ExtractFilePath(IN PFLT_CALLBACK_DATA data, OUT PWCHAR filePathBuffer)
{
	//retrieve the filename
	PFLT_FILE_NAME_INFORMATION fileNameInfomation;
	NTSTATUS status;

	status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfomation);
	if (!NT_SUCCESS(status))
		return status;

	//retrive the real file name
	status = FltParseFileNameInformation(fileNameInfomation);

	if (NT_SUCCESS(status))
	{
		if (fileNameInfomation->Name.Length < MAXIMUM_FILENAME_LENGTH) //keep last byte of buffer untouched (NUL byte)
			RtlCopyMemory(filePathBuffer, fileNameInfomation->Name.Buffer, fileNameInfomation->Name.Length); //Name.Length specifies the length in Bytes (doesnt include NUL-Byte)!
		else	
			status = STATUS_BUFFER_TOO_SMALL;	
	}

	FltReleaseFileNameInformation(fileNameInfomation);
	return status;
}

NTSTATUS CalcHash(IN LPCWSTR hashAlgorithmId, IN PCWSTR filePath, IN DWORD hexStrBufSize, OUT PCHAR hexStrBuf)
{
	NTSTATUS status;
	// --------------------------------- Variables in outer scope for hash preparation---------------------------------
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	PUCHAR pbHashObject = NULL;
	PUCHAR pbHash = NULL;
	// --------------------------------- Variables in outer scope for file access and hash halculation ---------------------------------
	HANDLE fileHandle = NULL;
	ULONG buffersize = BUFFERSIZE_READFILE_OPERATION;
	UCHAR readBuffer[BUFFERSIZE_READFILE_OPERATION]; // buffer for read operations

	// --------------------------------- do{}while(FALSE)-Loop for better Error Handling ---------------------------------
	do
	{
		// --------------------------------- Hash preparation ---------------------------------
		DWORD cbData = 0, cbHash = 0, cbHashObject = 0;

		//open an algorithm fileHandle
		status = BCryptOpenAlgorithmProvider(&hAlg, hashAlgorithmId, NULL, 0);
		if (!NT_SUCCESS(status))
			break;

		//calculate the size of the buffer to hold the hash object
		status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0);
		if (!NT_SUCCESS(status))
			break;
		
		//allocate the hash object on the heap
		pbHashObject = ExAllocatePoolWithTag(NonPagedPool, cbHashObject, HASH_OBJECT_TAG); //TODO: do we really need this on heap?
		if (NULL == pbHashObject)
		{
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}
			
		//calculate the length of the hash
		status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(DWORD), &cbData, 0);
		if (!NT_SUCCESS(status))
			break;

		//allocate the hash buffer on the heap
		pbHash = ExAllocatePoolWithTag(NonPagedPool, cbHash, HASH_DATA_TAG);
		if (NULL == pbHash)
		{
			status = STATUS_MEMORY_NOT_ALLOCATED;
			break;
		}

		//create a hash
		status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0);
		if (!NT_SUCCESS(status))
			break;

		// --------------------------------- File access and Hash Calculation ---------------------------------
		IO_STATUS_BLOCK ioStatusBlock;
		UNICODE_STRING uniName;
		OBJECT_ATTRIBUTES objAttr;

		RtlInitUnicodeString(&uniName, filePath);
		InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		status = ZwCreateFile(&fileHandle,
			GENERIC_READ,
			&objAttr, &ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ, // share the access with other threads
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL, 0);

		if (!NT_SUCCESS(status))
			break;

		LARGE_INTEGER offset;
		offset.QuadPart = 0;

		while (TRUE)
		{
			//reads from file to readBuffer
			status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, readBuffer, buffersize, &offset, NULL); //ZwReadFile returns count of read bytes in the param 'buffersize'
			if (status == STATUS_END_OF_FILE)
				break; //this is a valid and expected break condition

			if (!NT_SUCCESS(status)) //any other error code
				break; //breaks inner loop

			buffersize = PtrToUlong((PVOID)ioStatusBlock.Information); //buffersize stays always the same, until the last read operation when we reach EOF, so we shorten the buffersize, so that the next write operation writes only the first bytes in the actual buffer to the file
			offset.QuadPart += buffersize;

			//hash some data
			status = BCryptHashData(hHash, (PUCHAR)readBuffer, buffersize, 0);
			if (!NT_SUCCESS(status))
				break; //breaks inner loop
		}

		if (!NT_SUCCESS(status) && (status != STATUS_END_OF_FILE)) // inner while(TRUE) loop got broken by some error => break outer loop
			break;

		status = BCryptFinishHash(hHash, pbHash, cbHash, 0); // returns the actual hash in the buffer pbHash
		if (!NT_SUCCESS(status))
			break;

		status = BCryptCloseAlgorithmProvider(hAlg, 0);
		if (!NT_SUCCESS(status))
			break;

		status = BCryptDestroyHash(hHash);
		if (!NT_SUCCESS(status))
			break;

		//--------------------------------- Hexstring ---------------------------------
		//convert byte stream to hex string
		SIZE_T hexStrSize = cbHash * 2 + 1; //in case of SHA256 (32 Bytes) -> cbHash = 32 -> 64 HexDigits + NUL terminator = 65 bytes to allocate
		status = BytesToHexString(pbHash, cbHash, hexStrSize, hexStrBufSize, hexStrBuf);
		if (!NT_SUCCESS(status))
			break;

	} while (FALSE);

	// Cleanup in any case.
	// dont need to check the status of the "Close/Destroy" calls, because they could only return "STATUS_INVALID_HANDLE" in error case. We already check in the corresponding "Open/Create" calls for successful execution (thus also for valid handles)
	if (hAlg)
		BCryptCloseAlgorithmProvider(hAlg, 0);

	if (hHash)
		BCryptDestroyHash(hHash);
		
	if (pbHashObject)
		ExFreePoolWithTag(pbHashObject, HASH_OBJECT_TAG);

	if (pbHash)
		ExFreePoolWithTag(pbHash, HASH_DATA_TAG);

	if (fileHandle)
		ZwClose(fileHandle);

	return status;
}

NTSTATUS GetProcessImagePath(PEPROCESS pProcess, OUT PWCHAR imagePath)
{
	HANDLE hProcess; // It actually returns a handle to an object. its actually not a process handle (because its not a process processId)

	NTSTATUS status = ObOpenObjectByPointer(pProcess, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess); //this increments the reference count, rather than the handle count, so the OS will not delete the object while its still being referenced
	if (!NT_SUCCESS(status))
		return status;
	

	ULONG returnedSize;
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returnedSize);

	if (STATUS_INFO_LENGTH_MISMATCH != status) //we ignore this, since we know that we have passed a too small buffer size
	{
		ZwClose(hProcess);
		return status;
	}
		
	//create buffer
	WCHAR imagePathBuf[MAXIMUM_FILENAME_LENGTH];
	UNICODE_STRING uImagePath;
	uImagePath.Buffer = imagePathBuf;
	uImagePath.Length = 0x0;
	uImagePath.MaximumLength = sizeof(imagePathBuf);

	// Check if buffer is big enough to store the string
	if (uImagePath.MaximumLength < (returnedSize - sizeof(UNICODE_STRING)))
	{
		ZwClose(hProcess);
		return STATUS_BUFFER_OVERFLOW;
	}
		
	// retrieve the process image file name from the fileHandle
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		&uImagePath,
		returnedSize,
		&returnedSize);

	ZwClose(hProcess); 

	if (NT_SUCCESS(status))
		RtlCopyMemory(imagePath, uImagePath.Buffer, uImagePath.Length);

	return status;
}


VOID PrintObjectInformationsByHandle(HANDLE hObject)
{
	ULONG returnedSizeObj;
	PUBLIC_OBJECT_BASIC_INFORMATION objInfo;
	ULONG sz = sizeof(objInfo);

	NTSTATUS status = ZwQueryObject(hObject,
		ObjectBasicInformation,
		&objInfo, // buffer
		sz, // buffer size
		&returnedSizeObj);

	Log("val: %x | p: %p | addr: %p", hObject, hObject, &hObject);
	Log("status of ZwQueryObject: %x | sz: %lu | returnedSizeObj: %lu", status, sz, returnedSizeObj);

	ULONG handleCount = objInfo.HandleCount;
	ULONG pointerCount = objInfo.PointerCount;

	Log("handleCount: %lu | pointerCount: %lu", handleCount, pointerCount);
}