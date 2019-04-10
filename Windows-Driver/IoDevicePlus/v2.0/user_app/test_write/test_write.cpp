#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "../common/ioctl.h"
#include "../common/const.h"

#define MAX_BUFFER_LEN 512

#define MEM_NAME "my_memory"

int main()
{
	HANDLE hMemory = NULL;
	CHAR szName[MEM_NAME_LEN] = { 0 };
	CHAR pBuffer[MAX_BUFFER_LEN] = { 0 };

	printf("Memory name? ");
	scanf("%s", szName);
	hMemory = CreateSharedMemory(szName, MAX_BUFFER_LEN);
	//hMemory = CreateSharedMemory(MEM_NAME, MAX_BUFFER_LEN);
	if (hMemory != NULL)
	{
		while (1)
		{
			printf("Enter message, or \"q\" to exit >> ");
			scanf("%s", pBuffer);

			if (!strcmp(pBuffer, "q"))
				break;

			DWORD cb;
			if (WriteSharedMemory(hMemory, pBuffer, strlen(pBuffer) + 1, &cb))
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
	else
	{
		printf("CreateSharedMemory Error\n");
	}

	printf("\nPress any key to free shared memory and exit...");
	_getch();

	FreeSharedMemory(hMemory);
}
