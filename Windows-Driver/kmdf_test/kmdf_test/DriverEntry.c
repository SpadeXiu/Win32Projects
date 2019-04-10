#include <ntddk.h>

VOID UnLoadDriver(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KdPrint(("RegPath: %wZ", pRegPath));
	pDriverObject->DriverUnload = UnLoadDriver;
	return STATUS_SUCCESS;
}