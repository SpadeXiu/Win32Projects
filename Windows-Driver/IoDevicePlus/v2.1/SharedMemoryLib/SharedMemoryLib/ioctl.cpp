#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include "const.h"
#include "ioctl.h"


HANDLE g_hDevice = NULL;


HANDLE OpenSharedMemory(PSTR pszName)
{
	g_hDevice = CreateFile(
		DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		NULL);
	if (g_hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Open Device Error: #%d\n", GetLastError());
		return NULL;
	}
	else
	{
		printf("Open Device Successfully!\n");
	}

	HANDLE hMemory = NULL;
	if (0 != DeviceIoControl(g_hDevice, DEVICE_OPEN_MEM, pszName, strlen(pszName) + 1,
		NULL, 0, (DWORD*)&hMemory, NULL) && hMemory != NULL)
	{
		return hMemory;
	}
	return NULL;
}

DWORD ConnectSharedMemory(HANDLE hMemory)
{
	DWORD status = CONNECT_ERROR;
	if (0 != DeviceIoControl(g_hDevice, DEVICE_CONNECT, &hMemory, sizeof(hMemory),
		NULL, 0, &status, NULL))
	{
		// Succeeded. Do nothing.
	}
	return status;
}

HANDLE CreateSharedMemory(PSTR pszName, DWORD uSize)
{
	g_hDevice = CreateFile(
		DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		NULL);
	if (g_hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Open Device Error: #%d\n", GetLastError());
		return NULL;
	}
	else
	{
		printf("Open Device Successfully!\n");
	}

	HANDLE hMemory = NULL;
	CHAR pBuffer[sizeof(DWORD) + MEM_NAME_LEN];

	*(DWORD *)pBuffer = uSize;
	strncpy(pBuffer + sizeof(DWORD), pszName, MEM_NAME_LEN);
	if (0 != DeviceIoControl(g_hDevice, DEVICE_MEM_ALLOC, pBuffer, sizeof(pBuffer),
		NULL, 0, (DWORD*)&hMemory, NULL) && hMemory != NULL)
	{
		return hMemory;
	}
	return NULL;
}

BOOL ReadSharedMemory(HANDLE hMemory, PVOID pBuffer, DWORD nSize, PDWORD pBytesRead)
{
	if (pBuffer != NULL)
	{
		*(DWORD *)pBuffer = (DWORD)hMemory;
		if (0 != DeviceIoControl(g_hDevice, DEVICE_RECV_DATA, pBuffer, sizeof(DWORD),
			pBuffer, nSize, pBytesRead, NULL))
		{
			return TRUE;
		}
	}
	return FALSE;
}

BOOL WriteSharedMemory(HANDLE hMemory, PVOID pBuffer, DWORD nSize, PDWORD pBytesWritten)
{
	if (pBuffer != NULL)
	{
		DWORD _nSize = sizeof(DWORD) + nSize;
		PVOID _pBuffer = malloc(_nSize);
		if (_pBuffer != NULL)
		{
			*(DWORD *)_pBuffer = (DWORD)hMemory;
			memcpy((DWORD *)_pBuffer + 1, pBuffer, nSize);
			if (0 != DeviceIoControl(g_hDevice, DEVICE_SEND_DATA, _pBuffer, _nSize,
				NULL, 0, pBytesWritten, NULL))
			{
				return TRUE;
			}
			free(_pBuffer);
		}
	}
	return FALSE;
}

VOID FreeSharedMemory(HANDLE hMemory)
{
	DWORD dw;
	if (0 != DeviceIoControl(g_hDevice, DEVICE_MEM_FREE, &hMemory, sizeof(hMemory),
		NULL, 0, &dw, NULL))
	{
		// Succeed. Do nothing.
	}
}
