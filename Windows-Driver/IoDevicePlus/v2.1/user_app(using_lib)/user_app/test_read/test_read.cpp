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
	CHAR pRdBuffer[MAX_BUFFER_LEN] = { 0 };
	CHAR pWtBuffer[MAX_BUFFER_LEN] = { 0 };

	printf("Memory name? ");
	scanf("%s", szName);
	hMemory = OpenSharedMemory(szName);

	//hMemory = OpenSharedMemory(MEM_NAME);
	if (hMemory == NULL)
	{
		printf("Error: Invalid shared memory\n");
		return EXIT_FAILURE;
	}
	
	while (1)
	{
		printf("[Server] Enter message, or \"q\" to exit >> ");
		scanf("%s", pWtBuffer);

		if (!strcmp(pWtBuffer, "q"))
			break;

		DWORD cb;

		// Write会解除server的Read阻塞
		if (WriteSharedMemory(hMemory, pWtBuffer, strlen(pWtBuffer), &cb))
		{
			printf("[Client] Number of bytes written: %d\n", cb);
		}
		else
		{
			printf("[Client] WriteSharedMemory Error\n");
			break;
		}

		// Read被阻塞，直到server写入数据
		printf("[Client] wait for data to read...\n");
		if (ReadSharedMemory(hMemory, pRdBuffer, MAX_BUFFER_LEN, &cb))
		{
			printf("[Client] Number of bytes read: %d\n", cb);
			if (cb > 0)
			{
				pRdBuffer[cb] = 0;
				printf("[Client] Data read >> %s\n", pRdBuffer);
			}
		}
		else
		{
			printf("[Client] ReadSharedMemory Error\n");
			break;
		}
	}

	printf("\nPress any key to free shared memory and exit...");
	_getch();

	FreeSharedMemory(hMemory);
}