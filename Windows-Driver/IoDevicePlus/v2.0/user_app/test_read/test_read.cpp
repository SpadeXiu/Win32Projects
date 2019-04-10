#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include "../common/ioctl.h"
#include "../common/const.h"

#define MAX_BUFFER_LEN 512

#define MEM_NAME "my_memory"

void exit()
{
	printf("\nPress any key to exit...");
	_getch();
}

int main()
{
	HANDLE hMemory = NULL;
	CHAR szName[MEM_NAME_LEN] = { 0 };
	CHAR pBuffer[MAX_BUFFER_LEN] = { 0 };

	printf("Memory name? ");
	scanf("%s", szName);
	hMemory = OpenSharedMemory(szName);

	//hMemory = OpenSharedMemory(MEM_NAME);
	if (hMemory == NULL)
	{
		printf("Error: Invalid shared memory\n");
		exit();
		return EXIT_FAILURE;
	}
	
	while (1)
	{
		printf("Press any key to continue, or \"q\" to exit...");
		if (_getch() == 'q')
			break;

		DWORD cb;
		if (ReadSharedMemory(hMemory, pBuffer, MAX_BUFFER_LEN, &cb))
		{
			printf("\nReadSharedMemory succeeded! Number of bytes read: %d\n", cb);
			if (cb > 0)
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