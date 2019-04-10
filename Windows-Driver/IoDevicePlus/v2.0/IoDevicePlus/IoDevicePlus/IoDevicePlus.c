#include <ntddk.h>
#include "IoDevicePlus.h"

#define _DEBUG_

PDEVICE_OBJECT	g_pDeviceObject = NULL;
LIST_ENTRY		g_ListHead;
KSPIN_LOCK		g_ListLock;


PMEMORY_TABLE FindMemoryEntry(PSTR pszName)
{
	PLIST_ENTRY p;
	for (p = g_ListHead.Flink; p != &g_ListHead; p = p->Flink)
	{
		PMEMORY_TABLE pMemTbl = (PMEMORY_TABLE)
			CONTAINING_RECORD(p, MEMORY_TABLE, ListEntry);
		if (!strncmp(pszName, pMemTbl->Name, MEM_NAME_LEN))
			return pMemTbl;
	}
	return NULL;
}

BOOLEAN ContainMemoryEntry(PMEMORY_TABLE pMemTbl)
{
	PLIST_ENTRY p;
	for (p = g_ListHead.Flink; p != &g_ListHead; p = p->Flink)
	{
		if ((PMEMORY_TABLE)p == pMemTbl)
			return TRUE;
	}
	return FALSE;
}

BOOLEAN FreeMemoryEntry(PMEMORY_TABLE pMemTbl)
{
	BOOLEAN Flag = FALSE;
	if (pMemTbl && pMemTbl->MemBase)
	{
		PMEMORY_TABLE p = pMemTbl;

		// Free shared memory.
		ExFreePool(pMemTbl->MemBase);

		// Remove the entry from list.
		KIRQL irql;
		KeAcquireSpinLock(&g_ListLock, &irql);
		Flag = RemoveEntryList((PLIST_ENTRY)pMemTbl);
		KeReleaseSpinLock(&g_ListLock, irql);

		// Free the entry.
		ExFreePool(p);
	}
	return Flag;
}

VOID FreeMemoryTableList()
{
	PLIST_ENTRY p;
	for (p = g_ListHead.Flink; p->Flink != &g_ListHead; p = p->Flink)
	{
		FreeMemoryEntry((PMEMORY_TABLE)p);
	}
}

VOID InitRoutine()
{
	InitializeListHead(&g_ListHead);
	KeInitializeSpinLock(&g_ListLock);
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
	
	// Free list
	FreeMemoryTableList();

	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Retval = 0;
	PMEMORY_TABLE pMemTbl = NULL;

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
#ifdef _DEBUG_
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength > 0);
				ASSERT(OutputLength == 0);
#endif // _DEBUG_

				//
				// Server writes data to shared memory.
				//

				// A DWORD32 at the beginning of `pUserBuffer` is a "handle"
				// specified the unique entry of MEMORY_TABLE in the linked list.
				DWORD32 BytesToWrite = InputLength - sizeof(DWORD32);

				pMemTbl = (PMEMORY_TABLE)(*(DWORD32 *)pUserBuffer);
				if (pMemTbl && pMemTbl->MemBase)
				{
					if (ContainMemoryEntry(pMemTbl))
					{
						RtlZeroMemory(pMemTbl->MemBase, pMemTbl->MemLength);
						if (BytesToWrite <= pMemTbl->MemLength)
						{
							PCHAR pSrc = (PCHAR)pUserBuffer + sizeof(DWORD32);
							RtlCopyMemory(pMemTbl->MemBase, pSrc, BytesToWrite);

							pMemTbl->AvailableLength = BytesToWrite;
							Retval = BytesToWrite;
						}
						else
						{
							KdPrint(("Buffer length out of range\n"));
							Status = STATUS_INVALID_PARAMETER;
						}
					}
					else
					{
						KdPrint(("Shared memory broken\n"));
						Status = STATUS_INVALID_PARAMETER;
					}
				}
				else
				{
					KdPrint(("Invalid handle to shared memory\n"));
					Status = STATUS_INVALID_PARAMETER;
				}

				break;
			case DEVICE_RECV_DATA:
#ifdef _DEBUG_
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == sizeof(DWORD32));
				ASSERT(OutputLength > 0);
#endif // _DEBUG_

				//
				// Client reads data from "shared memory".
				//

				// Copy data from "shared memory".
				// NOTE: The number of bytes which client can read from shared memory
				//		 shouldn't go beyond `MEMORY_TABLE::AvailableLength`.

				// `pUserBuffer` is used as both input and output.

				// `pUserBuffer` as input buffer.
				pMemTbl = (PMEMORY_TABLE)(*(DWORD32 *)pUserBuffer);
				if (pMemTbl && pMemTbl->MemBase)
				{
					if (ContainMemoryEntry(pMemTbl))
					{
						// Before using `pUserBuffer` as output buffer, we should zero it.
						RtlZeroMemory(pUserBuffer,
							(OutputLength < sizeof(DWORD32) ? sizeof(DWORD32) : OutputLength));

						if (OutputLength <= pMemTbl->AvailableLength)
						{
							RtlCopyMemory(pUserBuffer, pMemTbl->MemBase, OutputLength);
							Retval = OutputLength;
						}
						else
						{
							RtlCopyMemory(pUserBuffer, pMemTbl->MemBase, pMemTbl->AvailableLength);
							Retval = pMemTbl->AvailableLength;
						}
					}
					else
					{
						KdPrint(("Shared memory broken\n"));
						Status = STATUS_INVALID_PARAMETER;
					}
				}
				else
				{
					KdPrint(("Invalid handle to shared memory\n"));
					Status = STATUS_INVALID_PARAMETER;
				}
				
				break;
			case DEVICE_MEM_ALLOC:
#ifdef _DEBUG_
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength > 0);
				ASSERT(OutputLength == 0);
#endif // _DEBUG_

				// 
				// Server allocates "shared memory".
				//

				// How many bytes of shared memory will be allocated?
				DWORD32 cb = *(DWORD32 *)pUserBuffer;

				// The unique name of shared memory.
				PSTR pszName = (PSTR)pUserBuffer + sizeof(DWORD32);

				if (FindMemoryEntry(pszName))
				{
					// MEMORY_TABLE entry named as `pszName` has
					// already been created.
					KdPrint(("Name \"%s\" is invalid\n", pszName));
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				// Allocate list entry.
				pMemTbl = (PMEMORY_TABLE)ExAllocatePoolWithTag(
					NonPagedPoolNx, sizeof(MEMORY_TABLE), MEM_TAG);
				if (pMemTbl != NULL)
				{
					// Allocate shared memory.
					pMemTbl->MemBase = ExAllocatePoolWithTag(
						NonPagedPoolNx, cb, MEM_TAG);
					if (pMemTbl->MemBase != NULL)
					{
						if (strlen(pszName) < MEM_NAME_LEN)
						{
							pMemTbl->MemLength = cb;
							pMemTbl->AvailableLength = 0;
							strncpy(pMemTbl->Name, pszName, MEM_NAME_LEN);

							RtlZeroMemory(pMemTbl->MemBase, pMemTbl->MemLength);

							ExInterlockedInsertHeadList(&g_ListHead, 
								(PLIST_ENTRY)pMemTbl, &g_ListLock);

							// The "handle" of allocated shared memory.
							Retval = (ULONG)pMemTbl;
						}
						else // The name is too long, invalid.
						{
							ExFreePool(pMemTbl);
							KdPrint(("Invalid name\n"));
							Status = STATUS_INVALID_PARAMETER;
						}
					}
					else
					{
						ExFreePool(pMemTbl);
						KdPrint(("Memory allocation (Shared Memory) error. Insufficent resources\n"));
						Status = STATUS_INSUFFICIENT_RESOURCES;
					}
				}
				else
				{
					KdPrint(("Memory allocation (MEMORY_TABLE) error. Insufficent resources\n"));
					Status = STATUS_INSUFFICIENT_RESOURCES;
				}

				break;
			case DEVICE_MEM_FREE:
#ifdef _DEBUG_
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == sizeof(DWORD32));
				ASSERT(OutputLength == 0);
#endif // _DEBUG_

				//
				// User app (client or server) requests to free its shared
				// memory entry in the list.
				//

				pMemTbl = (PMEMORY_TABLE)(*(DWORD32 *)pUserBuffer);
				FreeMemoryEntry(pMemTbl);

				break;
			case DEVICE_OPEN_MEM:
#ifdef _DEBUG_
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength > 0);
				ASSERT(OutputLength == 0);
#endif // _DEBUG_
				
				//
				// User app (client or server) requests for the handle
				// of shared memory via its name.
				//

				CHAR szName[MEM_NAME_LEN];
				strncpy(szName, pUserBuffer, MEM_NAME_LEN);

				pMemTbl = FindMemoryEntry(szName);
				if (pMemTbl != NULL)
				{
					Retval = (ULONG)pMemTbl;
				}
				else
				{
					KdPrint(("No matched shared memory found\n"));
					Retval = (ULONG)NULL;
					Status = STATUS_INVALID_PARAMETER;
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

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KdPrint(("\r\nRegPath: %wZ\r\n", pRegPath));
	pDriverObject->DriverUnload = UnloadDriver;

	InitRoutine();

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