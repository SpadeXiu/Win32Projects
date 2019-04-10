#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "../common/ioctl.h"

#define MAX_BUFFER_LEN 512

void exit()
{
	printf("\nPress any key to exit...");
	_getch();
}

int main()
{
	HANDLE hDevice = NULL;
	CHAR pBuffer[MAX_BUFFER_LEN] = { 0 };

	hDevice = OpenSharedMemory();
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Open Device Error: #%d\n", GetLastError());
		exit();
		return EXIT_FAILURE;
	}
	else
	{
		printf("Open Device Successfully!\n");
	}

	while (1)
	{
		printf("Press any key to continue, or \"q\" to exit...");
		if (_getch() == 'q')
			break;

		DWORD cb;
		if (ReadSharedMemory(hDevice, pBuffer, MAX_BUFFER_LEN, &cb))
		{
			printf("\nReadSharedMemory succeeded! Number of bytes read: %d\n", cb);
			printf(">> %s\n", pBuffer);
		}
		else
		{
			printf("ReadSharedMemory failed!\n");
			break;
		}
	}

	exit();
}