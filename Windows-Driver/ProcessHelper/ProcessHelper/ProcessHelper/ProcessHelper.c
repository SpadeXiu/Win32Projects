#include <ntddk.h>

#define OFFSET_CURRENT_THREAD		0x124
#define OFFSET_APC_STATE			0X40
#define OFFSET_PROCESS				0x10
#define OFFSET_DIR_TABLE_BASE		0x18
#define OFFSET_PID					0xb4
#define OFFSET_PROCESS_LINK			0xb8
#define OFFSET_IMAGE_FILENAME		0x16c


NTSTATUS EnumProcesses()
{
	PVOID pProcess, pCurProcess;
	PSTR pszImageFileName;
	DWORD32 dwProcessId;
	DWORD32 dwDirTableBase;

	__asm
	{
		mov eax, fs:[OFFSET_CURRENT_THREAD] // Get `CurrentThread`
			mov eax, [eax + OFFSET_APC_STATE] // Get `ApcState`
			mov eax, [eax + OFFSET_PROCESS] // Get `Process`
			mov pCurProcess, eax
	}

	pProcess = pCurProcess;
	do {
		dwDirTableBase = *(DWORD32*)((PSTR)pCurProcess + OFFSET_DIR_TABLE_BASE);
		dwProcessId = *(DWORD32*)((PSTR)pCurProcess + OFFSET_PID);
		pszImageFileName = (PSTR)pCurProcess + OFFSET_IMAGE_FILENAME;

		KdPrint(("Process Name: %s, PID: %d, Page Dir Table Base: 0x%.8x\r\n",
			pszImageFileName, dwProcessId, dwDirTableBase));

		// Next process
		pCurProcess = (PVOID)((*(DWORD32*)((PSTR)pCurProcess + OFFSET_PROCESS_LINK))
			- OFFSET_PROCESS_LINK);
	} while (pCurProcess != pProcess); // Ñ­»·Á´±íÅÐ¿Õ

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("UnloadDriver Success\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KdPrint(("\r\nRegPath: %wZ\r\n", pRegPath));
	pDriverObject->DriverUnload = UnloadDriver;

	EnumProcesses();

	return STATUS_SUCCESS;
}