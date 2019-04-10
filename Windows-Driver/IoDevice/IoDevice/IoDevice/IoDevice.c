#include <ntddk.h>

PDEVICE_OBJECT g_pDeviceObject = NULL;

#define DEVICE_SYMBOL_NAME L"\\??\\symlink_iodevice"

#define MAX_BUFFER_LEN 512

// @param `Function` 0~0x7ff are reserved by Microsoft

#define DEVICE_SEND_DATA \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x900, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#define DEVICE_RECV_DATA \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x901, \
					METHOD_BUFFERED, \
					FILE_READ_DATA)


VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	// Delete symbolic link
	UNICODE_STRING SymLinkName =
		RTL_CONSTANT_STRING(DEVICE_SYMBOL_NAME);
	IoDeleteSymbolicLink(&SymLinkName);

	// Delete device
	ASSERT(g_pDeviceObject != NULL);
	IoDeleteDevice(g_pDeviceObject);

	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG BytesReturned = 0;

	// Use stack location of current I/O request to get major function code.
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	// Is the request sent to the device object created just now?
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
			case DEVICE_SEND_DATA: // User app is sending data to kernel
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength > 0);
				ASSERT(OutputLength == 0);

				if (InputLength > MAX_BUFFER_LEN)
				{
					KdPrint(("Buffer length out of range.\r\n"));
					Status = STATUS_INVALID_PARAMETER;
					break;
				}

				KdPrint(("Received data>> %s", (PSTR)pUserBuffer));
				break;
			case DEVICE_RECV_DATA:  // User app wanna receive data from kernel
				ASSERT(pUserBuffer != NULL);
				ASSERT(InputLength == 0);
				ASSERT(OutputLength > 0);

				PSTR pMsg = "Data from kernel...\r\n";
				size_t cbMsg = strlen(pMsg) + 1;
				if (cbMsg > OutputLength)
				{
					KdPrint(("Buffer length out of range\r\n"));
					Status = STATUS_INVALID_PARAMETER;
					break;
				}
				// Copy data to buffer and user app will get it
				strncpy((PSTR)pUserBuffer, pMsg, cbMsg);
				BytesReturned = cbMsg;
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

	for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchRoutine;
	}

	NTSTATUS Status;
	UNICODE_STRING DeviceName =
		RTL_CONSTANT_STRING(L"\\Device\\readprocessmemory");
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