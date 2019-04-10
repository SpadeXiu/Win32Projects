#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "Header.h"

#define BUFFSIZE	16

BOOL WINAPI MyReadProcessMemory(
	_In_ DWORD dwProcessId,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead
)
{
	HANDLE hDevice = CreateFile(
		DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Open Device Error: #%d\n", GetLastError());
		return FALSE;
	}
	else
	{
		printf("Open Device Successfully!\n");
	}

	DWORD dw;

	ULONG argBuffer[3];
	argBuffer[0] = dwProcessId;
	argBuffer[1] = (ULONG)lpBaseAddress;
	argBuffer[2] = (ULONG)nSize;
	if (0 == DeviceIoControl(hDevice, DEVICE_SEND_DATA, argBuffer, sizeof(argBuffer),
		NULL, 0, &dw, NULL))
	{
		printf("Arguments sending error\n");
		CloseHandle(hDevice);
		return FALSE;
	}

	if (0 == DeviceIoControl(hDevice, DEVICE_RECV_DATA, NULL, 0,
		lpBuffer, nSize, &dw, NULL))
	{
		printf("Data receiving error\n");
		CloseHandle(hDevice);
		return FALSE;
	}

	*lpNumberOfBytesRead = dw;
	CloseHandle(hDevice);
	return TRUE;
}


int main()
{
	DWORD ProcessId;
	DWORD BaseAddress;
	CHAR buffer[BUFFSIZE] = { 0 };

	printf("[PID %d]\n", GetCurrentProcessId());

	printf("process id? ");
	scanf("%d", &ProcessId);

	printf("base address? ");
	scanf("%X", &BaseAddress);

	DWORD dw;

	HANDLE hProcess = OpenProcess(
		PROCESS_VM_READ,
		FALSE,
		ProcessId);
	if (hProcess != NULL)
	{
		printf("[ReadProcessMemory]");
		if (ReadProcessMemory(hProcess, (LPCVOID)BaseAddress, buffer, BUFFSIZE, &dw))
		{

			printf("Number of bytes read: %d\n", dw);
			for (int i = 0; i < dw; i++)
			{
				printf("%.2X ", (UCHAR)buffer[i]);
			}
			memset(buffer, 0, BUFFSIZE);
		}
	}

	printf("\n[MyReadProcessMemory]\n");
	if (MyReadProcessMemory(ProcessId, (LPCVOID)BaseAddress, buffer, BUFFSIZE, &dw))
	{
		printf("Number of bytes read: %d\n", dw);
		for (int i = 0; i < dw; i++)
		{
			printf("%.2X ", (UCHAR)buffer[i]);
		}
	}
	else
	{
		printf("MyReadProcessMemory error\n");
	}
	_getch();
}