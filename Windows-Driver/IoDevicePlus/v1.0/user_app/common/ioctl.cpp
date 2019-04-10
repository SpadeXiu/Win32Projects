#include "ioctl.h"
#include <stdio.h>

HANDLE OpenSharedMemory()
{
	HANDLE hDevice = CreateFile(
		DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		NULL);

	return hDevice;
}

HANDLE CreateSharedMemory(DWORD uSize)
{
	HANDLE hDevice = NULL;

	hDevice = CreateFile(
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
		return NULL;
	}
	else
	{
		printf("Open Device Successfully!\n");
	}


	DWORD cb;
	if (0 != DeviceIoControl(hDevice, DEVICE_MEM_ALLOC, &uSize, sizeof(uSize),
		NULL, 0, &cb, NULL))
	{
		return hDevice;
	}
	return NULL;
}

BOOL ReadSharedMemory(HANDLE hDevice, PVOID pBuffer, DWORD nSize, PDWORD pBytesRead)
{
	if (pBuffer != NULL)
	{
		if (0 != DeviceIoControl(hDevice, DEVICE_RECV_DATA, NULL, 0,
			pBuffer, nSize, pBytesRead, NULL))
		{
			return TRUE;
		}
	}
	return FALSE;
	
}

BOOL WriteSharedMemory(HANDLE hDevice, PVOID pBuffer, DWORD nSize, PDWORD pBytesWritten)
{
	if (pBuffer != NULL)
	{
		if (0 != DeviceIoControl(hDevice, DEVICE_SEND_DATA, pBuffer, nSize,
			NULL, 0, pBytesWritten, NULL))
		{
			return TRUE;
		}
	}
	return FALSE;
}

VOID DestorySharedMemory(HANDLE hDevice)
{
	CloseHandle(hDevice);
}