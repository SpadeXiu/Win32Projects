#include "ReadProcessMemory.h"

#define DEBUG

PDEVICE_OBJECT	g_pDeviceObject = NULL;
ULONG			g_ProcessId = 0;
ULONG			g_BaseAddress = 0;
ULONG			g_NumOfBytesToRead = 0;

/////////////////////////////////////////////////////////////////////////////

NTSTATUS GetProcessDirBase(ULONG ProcessId, PLONG pDirBase)
{
	PVOID pHdrProcess, pCurProcess;
	PSTR pszImageFileName;
	ULONG dwProcessId;
	ULONG dwDirBase;

	__asm
	{
		mov eax, fs:[OFFSET_CURRENT_THREAD] // Get `CurrentThread`
		mov eax, [eax + OFFSET_APC_STATE] // Get `ApcState`
		mov eax, [eax + OFFSET_PROCESS] // Get `Process`
		mov pCurProcess, eax
	}

	pHdrProcess = pCurProcess;
	do {
		dwDirBase = *(ULONG*)((PSTR)pCurProcess + OFFSET_DIR_TABLE_BASE);
		dwProcessId = *(ULONG*)((PSTR)pCurProcess + OFFSET_PID);
		pszImageFileName = (PSTR)pCurProcess + OFFSET_IMAGE_FILENAME;

		KdPrint(("Process Name: %s, PID: %d, Page Dir Table Base: 0x%.8x\r\n",
			pszImageFileName, dwProcessId, dwDirBase));

		if (ProcessId == dwProcessId)
		{
			// Target process found.
			*pDirBase = dwDirBase;
			break;
		}

		// Next process
		pCurProcess = (PVOID)((*(ULONG*)((PSTR)pCurProcess + OFFSET_PROCESS_LINK))
			- OFFSET_PROCESS_LINK);
	} while (pCurProcess != pHdrProcess);

	return STATUS_SUCCESS;
}

NTSTATUS SwitchDirBase(ULONG newDirBase, PLONG oldDirBase)
{
	__asm
	{
		// shield interruption
		cli
		// save old cr3
		mov eax, cr3
		mov ecx, oldDirBase
		mov [ecx], eax
		// switch to new cr3
		mov eax, newDirBase
		mov cr3, eax
	}

	return STATUS_SUCCESS;
}

NTSTATUS ResumeDirBase(ULONG oldDirBase)
{
	__asm
	{
		// resume old cr3
		mov eax, oldDirBase
		mov cr3, eax
		// resume interruption
		sti
	}

	return STATUS_SUCCESS;
}

NTSTATUS CopyProcessMemory(PVOID pTargetAddr, PVOID pBuffer, ULONG ulSize)
{
	RtlCopyMemory(pBuffer, pTargetAddr, ulSize);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Retval = 0;

	// Use stack location of current I/O request to get major function code.
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	// Is the request sent to our device object?
	if (pDeviceObject == g_pDeviceObject)
	{
		if ((pIrpStack->MajorFunction == IRP_MJ_CREATE) ||
			(pIrpStack->MajorFunction == IRP_MJ_CLOSE))
		{
			// `Create` and `Close` always succeed.
			// TODO nothing
		}
		else if (pIrpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
		{
			PVOID pUserBuffer = pIrp->AssociatedIrp.SystemBuffer;
			ULONG InputLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
			ULONG OutputLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

			switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
			{
			case DEVICE_SEND_DATA:
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength > 0);
				ASSERT(OutputLength == 0);

				// `pUserBuffer` contains three parts of information:
				// + ---------- + ---------------------- + ----------------------- +
				// | process id | base addr to read from | number of bytes to read |
				// + ---------- + ---------------------- + ----------------------- +
				
				g_ProcessId = *(PLONG)pUserBuffer;
				g_BaseAddress = *((PLONG)pUserBuffer + 1);
				g_NumOfBytesToRead = *((PLONG)pUserBuffer + 2);

				Retval = InputLength;

				break;
			case DEVICE_RECV_DATA:
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == 0);
				ASSERT(OutputLength == g_NumOfBytesToRead);
				ASSERT(g_ProcessId != 0);
				ASSERT(g_BaseAddress != 0);
				ASSERT(g_NumOfBytesToRead > 0);

				ULONG newDirBase, oldDirBase;
				GetProcessDirBase(g_ProcessId, &newDirBase);

				PCHAR pBuffer = (PCHAR)ExAllocatePoolWithTag(
					NonPagedPoolNx, g_NumOfBytesToRead, MEM_TAG);
				if (pBuffer != NULL)
				{
					SwitchDirBase(newDirBase, &oldDirBase);
#ifdef DEBUG
					KdPrint(("Dir base of current process : 0x%.8X", oldDirBase));
					KdPrint(("Dir base of target process : 0x%.8X", newDirBase));
#endif // DEBUG
					RtlCopyMemory(pBuffer, (PCHAR)g_BaseAddress, g_NumOfBytesToRead);
					ResumeDirBase(oldDirBase);

					RtlCopyMemory(pUserBuffer, pBuffer, g_NumOfBytesToRead);
					ExFreePool(pBuffer);
					
					Retval = g_NumOfBytesToRead;
				}
				else
				{
					KdPrint(("Memory allocation error\n"));
					Status = STATUS_INTERNAL_ERROR;
				}
	
				break;
			default:
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
	}

	pIrp->IoStatus.Information = Retval; // How many bytes are returned to user app?
	pIrp->IoStatus.Status = Status; // status when I/O request completes
	IoCompleteRequest(pIrp, IO_NO_INCREMENT); // Complete I/O request

	return Status;
}

/////////////////////////////////////////////////////////////////////////////

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KdPrint(("\r\nRegPath: %wZ\r\n", pRegPath));
	pDriverObject->DriverUnload = UnloadDriver;

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchRoutine;
	}

	NTSTATUS Status;
	UNICODE_STRING DeviceName =
		RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING SymLinkName =
		RTL_CONSTANT_STRING(DEVICE_SYMBOL_NAME);

	Status = IoCreateDevice(
		pDriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&g_pDeviceObject);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("IoCreateDevice Error. DeviceName: %wZ", DeviceName));
		return Status;
	}

	IoDeleteSymbolicLink(&SymLinkName);
	Status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("IoCreateSymbolicLink Error. SymLinkName: %wZ", SymLinkName));
		IoDeleteDevice(g_pDeviceObject);
		return Status;
	}

	return STATUS_SUCCESS;
}