#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <conio.h>
#include "Monitor.h"

int main()
{
	int err_code = EXIT_FAILURE;
	DWORD dwProcessId = 0;
	WCHAR szLibFilePath[MAX_PATH] = { 0 };
	PWCHAR pFileName = NULL;
	
	printf("Process Id? ");
	scanf("%ld", &dwProcessId);

	// È¡ Hook.DLL ¾ø¶ÔÂ·¾¶
	GetModuleFileName(NULL, szLibFilePath, MAX_PATH);
	pFileName = wcsrchr(szLibFilePath, '\\') + 1;
	lstrcpy(pFileName, TEXT("Hook.DLL"));

	Monitor monitor = Monitor(dwProcessId, szLibFilePath);
	if (!monitor.EnablePrivilege(SE_DEBUG_NAME))
	{
		printf("Failure to enable privilege!\n");
	}
	else
	{
		printf("Success to enable privilege!\n");
	}

	if (monitor.InjectLib())
	{
		if (monitor.EjectLib())
		{
			err_code = EXIT_SUCCESS;
		}
	}

	if (err_code == EXIT_SUCCESS)
	{
		printf("Injection/Ejection succeeded!\n");
	}
	else
	{
		printf("Injection failed! Error code: #%d\n", GetLastError());
	}

	printf("Precess any key to exit...");
	_getch();

	return err_code;
}