#include <stdio.h>
#include <Windows.h>

int g_i = 0x12345678;

int main()
{
	printf("0x%X\n", g_i);
	MessageBox(NULL, TEXT("Hello"), TEXT("World"), MB_OK);
	while(1){}
}