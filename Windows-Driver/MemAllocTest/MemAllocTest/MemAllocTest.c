#include <ntddk.h>

#define MEM_TAG 'MYTG'


VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KdPrint(("RegPath: %wZ", pRegPath));
	pDriverObject->DriverUnload = UnloadDriver;

	UNICODE_STRING pDst = { 0 };
	UNICODE_STRING pSrc = RTL_CONSTANT_STRING(L"Memory Test String");

	pDst.Buffer = (PWCH)ExAllocatePoolWithTag(
		NonPagedPoolNx, pSrc.Length + 1, MEM_TAG);
	if (pDst.Buffer == NULL)
	{
		KdPrint(("Memory allocation error. Insufficent resources\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	pDst.Length = pDst.MaximumLength = pSrc.Length + 1;

	//
	// Print memory content after allocation.
	//
	PSTR p = (PSTR)pDst.Buffer;
	KdPrint(("\nAfter allocation...\n"));
	for (ULONG i = 0; i < pDst.Length; i++)
	{
		KdPrint(("%.2X ", (UINT8)*p++));
	}

	RtlCopyUnicodeString(&pDst, &pSrc);
	KdPrint(("Dst buffer: %wZ\n", &pDst));

	//
	// Print memory content after copy.
	//
	p = (PSTR)pDst.Buffer;
	KdPrint(("\nAfter copy...\n"));
	for (ULONG i = 0; i < pDst.Length; i++)
	{
		KdPrint(("%.2X ", (UINT8)*p++));
	}

	
	//
	// Print memory content after free.
	//
	ExFreePool(pDst.Buffer);
	p = (PSTR)pDst.Buffer;
	KdPrint(("\nAfter free...\n"));
	for (ULONG i = 0; i < pDst.Length; i++)
	{
		KdPrint(("%.2X ", (UINT8)*p++));
	}

	pDst.Buffer = NULL;
	pDst.Length = pDst.MaximumLength = 0;

	return STATUS_SUCCESS;
}