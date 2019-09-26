#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include "pe_file_helper.h"

//#define DEBUG

int _tmain(int argc, wchar_t **argv)
{
#ifdef DEBUG
	PeFileHelper pe_file_helper(TEXT("testApp.exe"));
	pe_file_helper.InjectDll("testdll.dll", "dummy");
#else
	if (argc != 4) {
		printf("usage: %ws <pe_file_name> <dll_name> <dll_export_proc_name>\n", argv[0]);
		return 1;
	}

	PeFileHelper pe_file_helper(argv[1]);
	char dll_name[MAX_PATH], proc_name[32];
	sprintf(dll_name, "%ws", argv[2]);
	sprintf(proc_name, "%ws", argv[3]);
	pe_file_helper.InjectDll(dll_name, proc_name);

#endif
}