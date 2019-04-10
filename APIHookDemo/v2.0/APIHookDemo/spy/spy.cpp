#include <Windows.h>

int WINAPI SpyApiCalling(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
	DWORD dwProcessId;
	CHAR szMessage[64];

	dwProcessId = GetCurrentProcessId();
	wsprintfA(szMessage, "Process %d is calling MessageBoxW.", dwProcessId);
	// `MessageBoxW` is hooked, so we use `MessageBoxA`.
	MessageBoxA(0, szMessage, "API Hook", MB_OK);

	return 0;
}