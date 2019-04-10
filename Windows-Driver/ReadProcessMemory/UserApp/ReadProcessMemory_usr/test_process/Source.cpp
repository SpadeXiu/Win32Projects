#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>

#define MALLOC_SIZE	16

int main()
{
	char *p_mem = (char*)malloc(MALLOC_SIZE);
	memset(p_mem, 'A', MALLOC_SIZE);

	printf("process [%d] malloc base: 0x%.8X\n", GetCurrentProcessId(), (int)p_mem);
	for (int i = 0; i < MALLOC_SIZE; i++)
	{
		printf("%.2X ", (unsigned char)p_mem[i]);
	}

	_getch();
	free(p_mem);
	return 0;
}