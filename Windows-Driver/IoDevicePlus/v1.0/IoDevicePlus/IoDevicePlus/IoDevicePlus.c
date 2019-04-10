#include <ntddk.h>
#include "IoDevicePlus.h"

PDEVICE_OBJECT g_pDeviceObject = NULL;

MEMORY_TABLE g_MemTable;


VOID InitialMemoryTable()
{
	g_MemTable.MemBase = NULL;
	g_MemTable.MemLength = g_MemTable.AvailableLength = 0;
	g_MemTable.Freed = FALSE;
}

VOID FreeMemoryTable()
{
	if ((g_MemTable.MemBase != NULL) &&
		(g_MemTable.Freed == FALSE))
	{
		ExFreePool(g_MemTable.MemBase);
		g_MemTable.Freed = TRUE;
	}

	g_MemTable.MemLength = g_MemTable.AvailableLength = 0;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	// Delete symbolic link
	UNICODE_STRING SymLinkName =
		RTL_CONSTANT_STRING(DEVICE_SYMBOL_NAME);
	IoDeleteSymbolicLink(&SymLinkName);

	// Delete device
	if (g_pDeviceObject != NULL)
		IoDeleteDevice(g_pDeviceObject);

	// Free memory
	FreeMemoryTable();

	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG BytesReturned = 0;

	// Use stack location of current I/O request to get major function code.
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	// Is the request sent to our device object?
	if (pDeviceObject == g_pDeviceObject)
	{
		if (pIrpStack->MajorFunction == IRP_MJ_CREATE)
		{
			// `Create` always succeed.
			// TODO nothing
		}
		else if (pIrpStack->MajorFunction == IRP_MJ_CLOSE)
		{
			FreeMemoryTable();
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
				ASSERT(g_MemTable.MemBase != NULL);

				//
				// Server writes data to shared memory.
				//

				// NOTE: shared memory may be written repeatedly.
				RtlZeroMemory(g_MemTable.MemBase, g_MemTable.MemLength);

				DWORD32 BytesToWrite = InputLength;
				if (BytesToWrite <= g_MemTable.MemLength)
				{
					RtlCopyMemory(
						g_MemTable.MemBase,
						pUserBuffer,
						BytesToWrite);

					// Update g_MemTable.AvailableLength.
					g_MemTable.AvailableLength = BytesToWrite;

					BytesReturned = BytesToWrite;
				}
				else
				{
					KdPrint(("Buffer length out of range\n"));
					Status = STATUS_INVALID_PARAMETER;
				}

				break;
			case DEVICE_RECV_DATA:
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == 0);
				ASSERT(OutputLength > 0);
				ASSERT(g_MemTable.MemBase != NULL);

				//
				// Client reads data from "shared memory".
				//

				// Copy data from "shared memory".
				// NOTE: The number of bytes which client can read from
				//		 shared memory shouldn't go beyond `g_MemTable.AvailableLength`.
				if (OutputLength <= g_MemTable.AvailableLength)
				{
					RtlCopyMemory(
						pUserBuffer, 
						g_MemTable.MemBase,
						OutputLength);

					BytesReturned = OutputLength;
				}
				else
				{
					RtlCopyMemory(
						pUserBuffer,
						g_MemTable.MemBase,
						g_MemTable.AvailableLength);

					BytesReturned = g_MemTable.AvailableLength;
				}
				
				break;
			case DEVICE_MEM_ALLOC:
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == sizeof(DWORD32));
				ASSERT(OutputLength == 0);

				// 
				// Server allocates "shared memory".
				//

				// When server requests to allocate shared memory,
				// it should only put a DWORD into input buffer which
				// specify the length of memory it needs.

				// Extract "length of memory" and allocate them.
				DWORD32 cb = *(DWORD32 *)pUserBuffer;
				g_MemTable.MemBase = ExAllocatePoolWithTag(
					NonPagedPoolNx, cb, MEM_TAG);
				if (g_MemTable.MemBase != NULL)
				{
					g_MemTable.MemLength = cb;
					g_MemTable.AvailableLength = 0; // nothing available
					g_MemTable.Freed = FALSE;

					// Zero memory
					RtlZeroMemory(g_MemTable.MemBase, g_MemTable.MemLength);
				}
				else
				{
					KdPrint(("Memory allocation error. Insufficent resources\n"));
					Status = STATUS_INSUFFICIENT_RESOURCES;
				}

				break;
			default:
				Status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
	}

	pIrp->IoStatus.Information = BytesReturned; // How many bytes are returned to user app?
	pIrp->IoStatus.Status = Status; // status when I/O request completes
	IoCompleteRequest(pIrp, IO_NO_INCREMENT); // Complete I/O request

	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KdPrint(("\r\nRegPath: %wZ\r\n", pRegPath));
	pDriverObject->DriverUnload = UnloadDriver;

	InitialMemoryTable();

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