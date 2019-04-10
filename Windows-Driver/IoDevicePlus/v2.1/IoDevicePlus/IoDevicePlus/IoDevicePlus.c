#include <ntddk.h>
#include "IoDevicePlus.h"

#define _DEBUG_

PDEVICE_OBJECT	g_pDeviceObject = NULL;
LIST_ENTRY		g_ListHead;
KSPIN_LOCK		g_ListLock;
KSPIN_LOCK		g_MutexLock;


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
	if (ContainMemoryEntry(pMemTbl))
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
	KeInitializeSpinLock(&g_MutexLock);
}

VOID Unblock(PMEMORY_TABLE pMemTbl)
{
	if (ContainMemoryEntry(pMemTbl))
	{
		KIRQL irql;
		KeAcquireSpinLock(&g_MutexLock, &irql);
		if ((ULONG)PsGetCurrentProcessId() == pMemTbl->ServerId)
		{
			pMemTbl->ClientBlockStatus = NON_BLOCKING;
		}
		else if ((ULONG)PsGetCurrentProcessId() == pMemTbl->ClientId)
		{
			pMemTbl->ServerBlockStatus = NON_BLOCKING;
		}
		KeReleaseSpinLock(&g_MutexLock, irql);
	}
}

VOID Block(PMEMORY_TABLE pMemTbl)
{
	if (ContainMemoryEntry(pMemTbl))
	{
		if ((ULONG)PsGetCurrentProcessId() == pMemTbl->ClientId)
		{
			pMemTbl->ClientBlockStatus = BLOCKING;
			while (pMemTbl->ClientBlockStatus != NON_BLOCKING &&
				pMemTbl->ConnectStatus == CONNECT_SUCCESS);
		}
		else if ((ULONG)PsGetCurrentProcessId() == pMemTbl->ServerId)
		{
			pMemTbl->ServerBlockStatus = BLOCKING;
			while (pMemTbl->ServerBlockStatus != NON_BLOCKING &&
				pMemTbl->ConnectStatus == CONNECT_SUCCESS);
		}
	}
}

VOID WaitForConnection(PMEMORY_TABLE pMemTbl)
{
	if (ContainMemoryEntry(pMemTbl))
	{
		while (pMemTbl->ConnectStatus != CONNECT_SUCCESS);
	}
}

VOID CloseConnection(PMEMORY_TABLE pMemTbl)
{
	if (ContainMemoryEntry(pMemTbl))
	{
		KIRQL irql;
		KeAcquireSpinLock(&g_MutexLock, &irql);
		pMemTbl->ConnectStatus = CONNECT_ERROR;
		KeReleaseSpinLock(&g_MutexLock, irql);
	}
}

VOID EstablishConnection(PMEMORY_TABLE pMemTbl)
{
	if (ContainMemoryEntry(pMemTbl))
	{
		KIRQL irql;
		KeAcquireSpinLock(&g_MutexLock, &irql);
		pMemTbl->ConnectStatus = CONNECT_SUCCESS;
		KeReleaseSpinLock(&g_MutexLock, irql);
	}
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

				// A ULONG at the beginning of `pUserBuffer` is a "handle"
				// specified the unique entry of MEMORY_TABLE in the linked list.
				ULONG BytesToWrite = InputLength - sizeof(ULONG);

				pMemTbl = (PMEMORY_TABLE)(*(ULONG *)pUserBuffer);
				if (pMemTbl && pMemTbl->MemBase)
				{
					if (ContainMemoryEntry(pMemTbl))
					{
						RtlZeroMemory(pMemTbl->MemBase, pMemTbl->MemLength);
						if (BytesToWrite <= pMemTbl->MemLength)
						{
							PCHAR pSrc = (PCHAR)pUserBuffer + sizeof(ULONG);
							RtlCopyMemory(pMemTbl->MemBase, pSrc, BytesToWrite);

							pMemTbl->AvailableLength = BytesToWrite;
							Retval = BytesToWrite;

							// If it is server who is writing to shared memory,
							// then unblock client;
							// else if it is client, then unblock server.
							Unblock(pMemTbl);
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
				ASSERT(InputLength == sizeof(ULONG));
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
				pMemTbl = (PMEMORY_TABLE)(*(ULONG *)pUserBuffer);
				if (pMemTbl && pMemTbl->MemBase)
				{
					if (ContainMemoryEntry(pMemTbl))
					{
						// Before using `pUserBuffer` as output buffer, we should zero it.
						RtlZeroMemory(pUserBuffer,
							(OutputLength < sizeof(ULONG) ? sizeof(ULONG) : OutputLength));

						// Block client or server
						Block(pMemTbl);

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

				if (pMemTbl->ConnectStatus == CONNECT_ERROR)
				{
					KdPrint(("Shared memory disconnected\n"));
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
				ULONG cb = *(ULONG *)pUserBuffer;

				// The unique name of shared memory.
				PSTR pszName = (PSTR)pUserBuffer + sizeof(ULONG);

				pMemTbl = FindMemoryEntry(pszName);
				if (pMemTbl != NULL)
				{
					KdPrint(("Shared memory \"%s\" has alread existed.", pszName));
					Status = STATUS_INVALID_PARAMETER;
					Retval = (ULONG)NULL;
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
							pMemTbl->ServerId = (ULONG)PsGetCurrentProcessId();
							pMemTbl->ClientBlockStatus = BLOCKING;
							pMemTbl->ServerBlockStatus = BLOCKING;
							pMemTbl->ConnectStatus = CONNECT_ERROR;

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
				ASSERT(InputLength == sizeof(ULONG));
				ASSERT(OutputLength == 0);
#endif // _DEBUG_

				//
				// User app (client or server) requests to free its shared
				// memory entry.
				//

				pMemTbl = (PMEMORY_TABLE)(*(ULONG *)pUserBuffer);
				CloseConnection(pMemTbl);
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
					pMemTbl->ClientId = (ULONG)PsGetCurrentProcessId();
					EstablishConnection(pMemTbl);
					Retval = (ULONG)pMemTbl;
				}
				else
				{
					KdPrint(("No matched shared memory found\n"));
					Retval = (ULONG)NULL;
					Status = STATUS_INVALID_PARAMETER;
				}

				break;
			case DEVICE_CONNECT:
#ifdef _DEBUG_
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == sizeof(ULONG));
				ASSERT(OutputLength == 0);
#endif // _DEBUG_
				
				//
				// Server wait for client to connect.
				//
				
				pMemTbl = (PMEMORY_TABLE)(*(ULONG *)pUserBuffer);
				
				// Check the staus of connection until it is estabished.
				WaitForConnection(pMemTbl);
				Retval = CONNECT_SUCCESS;

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