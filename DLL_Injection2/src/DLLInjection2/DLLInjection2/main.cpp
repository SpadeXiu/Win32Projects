#include <Windows.h>
#include <iostream>
#include "pe_file_helper.h"

int main()
{
	PeFileHelper pe_file(TEXT("testApp.exe"));
	pe_file.InjectDll("testdll.dll", "dummy");
}