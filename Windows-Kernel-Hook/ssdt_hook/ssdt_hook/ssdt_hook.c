#include <ntddk.h>
#include "ssdt_hook.h"

static NT_READ_FILE  g_OrigNtReadFile  = NULL;
static NT_WRITE_FILE g_OrigNtWriteFile = NULL;


/////////////////////////////////////////////////////////////////////////

NTSTATUS NTAPI MyNtReadFile(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	)
{
	DbgPrint("PID %d is calling NtReadFile\r\n", PsGetCurrentProcessId());

	return g_OrigNtReadFile(FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		Buffer,
		Length,
		ByteOffset,
		Key);
}


NTSTATUS NTAPI MyNtWriteFile(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_In_    PVOID             Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	)
{
	DbgPrint("PID %d is calling NtWriteFile\r\n", PsGetCurrentProcessId());

	return g_OrigNtWriteFile(FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		Buffer,
		Length,
		ByteOffset,
		Key);
}

/////////////////////////////////////////////////////////////////////////


VOID DisableWriteProtect()
{
	_asm
	{
		mov eax, cr0;
		and eax, CR0_WP_DISABLE_MASK;
		mov cr0, eax;
		cli;
	}
}

VOID EnableWriteProtect()
{
	_asm
	{
		mov eax, cr0;
		or eax, ~CR0_WP_DISABLE_MASK;
		mov cr0, eax;
		sti;
	}
}

VOID SsdtHook(PVOID pFuncToHook, PVOID pNewFunc, PVOID *ppOldFunc)
{
	ULONG serviceId; // index of function in the SSDT
	PVOID pOldFunc = NULL;

	serviceId = *(PULONG)((PCHAR)pFuncToHook + 1);

	pOldFunc = (PVOID)KeServiceDescriptorTable.ServiceTableBase[serviceId];

	if (ppOldFunc != NULL)
		*ppOldFunc = pOldFunc;

	DisableWriteProtect();
	KeServiceDescriptorTable.ServiceTableBase[serviceId] = (ULONG)pNewFunc;
	EnableWriteProtect();
}

/////////////////////////////////////////////////////////////////////////

VOID UnLoadDriver(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = UnLoadDriver;

	UNICODE_STRING _ZwReadFile = RTL_CONSTANT_STRING(L"ZwReadFile");
	UNICODE_STRING _ZwWriteFile = RTL_CONSTANT_STRING(L"ZwWriteFile");

	PVOID pZwReadFile = MmGetSystemRoutineAddress(&_ZwReadFile);
	PVOID pZwWriteFile = MmGetSystemRoutineAddress(&_ZwWriteFile);

	SsdtHook(pZwReadFile, (PVOID)MyNtReadFile, (PVOID*)&g_OrigNtReadFile);
	SsdtHook(pZwWriteFile, (PVOID)MyNtWriteFile, (PVOID*)&g_OrigNtWriteFile);

	return STATUS_SUCCESS;
}
