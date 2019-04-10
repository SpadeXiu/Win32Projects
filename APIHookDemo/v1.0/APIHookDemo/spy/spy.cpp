#include <Windows.h>

int WINAPI SpyApiCalling(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
	DWORD dwProcessId;
	CHAR szMessage[128];

	dwProcessId = GetCurrentProcessId();
	wsprintfA(szMessage, "Process %d is calling MessageBoxW.", dwProcessId);
	MessageBoxA(0, szMessage, "API Hook", MB_OK);

	return 0;
}