#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "../common/ioctl.h"

#define MAX_BUFFER_LEN 512

void exit(HANDLE hDevice)
{
	printf("\nPress any key to free shared memory and exit...");
	_getch();
	DestorySharedMemory(hDevice);
}

int main()
{
	HANDLE hDevice = NULL;
	CHAR pBuffer[MAX_BUFFER_LEN] = { 0 };

	hDevice = CreateSharedMemory(MAX_BUFFER_LEN);
	if (hDevice != NULL)
	{
		while (1)
		{
			printf("Enter message, or \"q\" to exit >> ");
			scanf("%s", pBuffer);

			if (!strcmp(pBuffer, "q"))
				break;

			DWORD cb;
			if (WriteSharedMemory(hDevice, pBuffer, strlen(pBuffer) + 1, &cb))
			{
				printf("Write succeeded! Number of bytes written: %d\n", cb);
			}
			else
			{
				printf("Write failed!\n");
				break;
			}
		}
		
	}

	exit(hDevice);
}
