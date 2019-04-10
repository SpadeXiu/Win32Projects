#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "../common/include/ioctl.h"

#define MAX_BUFFER_LEN 512

#define MEM_NAME "my_memory"
#define MEM_NAME_LEN	16

int main()
{
	HANDLE hMemory = NULL;
	CHAR szName[MEM_NAME_LEN] = { 0 };
	CHAR pWtBuffer[MAX_BUFFER_LEN] = { 0 };
	CHAR pRdBuffer[MAX_BUFFER_LEN] = { 0 };

	printf("Memory name? ");
	scanf("%s", szName);
	hMemory = CreateSharedMemory(szName, MAX_BUFFER_LEN);
	//hMemory = CreateSharedMemory(MEM_NAME, MAX_BUFFER_LEN);

	printf("Wait for the connection of client...\n");
	if (hMemory != NULL &&
		CONNECT_SUCCESS == ConnectSharedMemory(hMemory))
	{
		printf("Connection established!\n");
		while (1)
		{
			DWORD cb;

			// Read被阻塞，直到client写入数据
			printf("[Server] wait for data to read...\n");
			if (ReadSharedMemory(hMemory, pRdBuffer, MAX_BUFFER_LEN, &cb))
			{
				printf("[Server] Number of bytes read: %d\n", cb);
				if (cb > 0)
				{
					pRdBuffer[cb] = 0;
					printf("[Server] Data read >> %s\n", pRdBuffer);
				}
			}
			else
			{
				printf("[Server] ReadSharedMemory Error\n");
				break;
			}

			printf("[Server] Enter message, or \"q\" to exit >> ");
			scanf("%s", pWtBuffer);

			if (!strcmp(pWtBuffer, "q"))
				break;

			// Write会解除client的Read阻塞
			if (WriteSharedMemory(hMemory, pWtBuffer, strlen(pWtBuffer), &cb))
			{
				printf("[Server] Number of bytes written: %d\n", cb);
			}
			else
			{
				printf("[Server] WriteSharedMemory Error\n");
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
