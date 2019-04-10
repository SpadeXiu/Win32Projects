#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <tchar.h>
#include "resource.h"

#define chMB(msg) MessageBoxA(GetActiveWindow(),msg,"MSG",MB_OK)
#define chERROR(msg) MessageBoxA(GetActiveWindow(),msg,"ERROR",MB_ICONERROR)

#define ERR_BUFSIZE 32

DWORD g_dwProcessId = 0;
WCHAR g_szLibFilepath[MAX_PATH] = { 0 };


////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI InjectLib(DWORD dwProcessId, PCWSTR pszLibFile) {
	BOOL bOk = FALSE;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	PWSTR pszLibFileRemote = NULL;

	__try {
		// Get a handle of the target process
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess == NULL)
			__leave;

		// Calculate the number of bytes needed for DLL's pathname
		int cch = lstrlenW(pszLibFile) + 1;
		int cb = cch * sizeof(wchar_t);

		// Allocate space in the remote process for DLL's pathname
		pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
		if (pszLibFileRemote == NULL)
			__leave;

		// Copy the DLL's pathname to the remote process' address space
		if (!WriteProcessMemory(hProcess, (LPVOID)pszLibFileRemote, pszLibFile, cb, NULL))
			__leave;

		// Get the real address of LoadLibraryw in kerne32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryW");
		if (pfnThreadRtn == NULL)
			__leave;

		// Create a remote thread which calls LoadLibraryW()
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, pszLibFileRemote, 0, NULL);
		if (hThread == NULL)
			__leave;

		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE; // Eveything executed successfully
	}
	__finally {
		if (pszLibFileRemote != NULL)
			VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return bOk;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI EjectLib(DWORD dwProcessId, PCWSTR pszLibFile) {
	BOOL bOk = FALSE;
	HANDLE hSnapshot = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	__try {
		// Grab a snapshot of the process
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
		if (hSnapshot == INVALID_HANDLE_VALUE)
			__leave;

		// Get the MODULE of the injected library
		MODULEENTRY32 me = { sizeof(me) };
		BOOL bFound = FALSE;
		BOOL bMoreMods = Module32First(hSnapshot, &me);
		for (;bMoreMods;bMoreMods = Module32Next(hSnapshot, &me)) {
			bFound = (lstrcmp(me.szModule, pszLibFile) == 0 ||
				lstrcmp(me.szExePath, pszLibFile) == 0);
			if (bFound) break;
		}
		if (!bFound) __leave;

		// Get the handle of the target process
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
		if (hProcess == NULL)
			__leave;

		// Get the real address of FreeLibrary in kerne32.dll
		PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)
			GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "FreeLibrary");
		if (pfnThreadRtn == NULL)
			__leave;

		// Create a remote thread which calls FreeLibrary()
		hThread = CreateRemoteThread(hProcess, NULL, 0,
			pfnThreadRtn, me.hModule, 0, NULL);
		if (hThread == NULL)
			__leave;

		// Wait for the remote thread to terminate
		WaitForSingleObject(hThread, INFINITE);

		bOk = TRUE; // Eveything executed successfully
	}
	__finally {
		if (hSnapshot != NULL)
			CloseHandle(hSnapshot);

		if (hThread != NULL)
			CloseHandle(hThread);

		if (hProcess != NULL)
			CloseHandle(hProcess);
	}

	return bOk;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// unused, reserved
// `szPrivilege` can be `SE_DEBUG_NAME`
BOOL EnablePrivilege(PCTSTR szPrivilege, BOOL fEnable) {

   // Enabling the debug privilege allows the application to see
   // information about service applications
   BOOL fOk = FALSE;    // Assume function fails
   HANDLE hToken;

   // Try to open this process's access token
   if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, 
      &hToken)) {

      // Attempt to modify the given privilege
      TOKEN_PRIVILEGES tp;
      tp.PrivilegeCount = 1;
      LookupPrivilegeValue(NULL, szPrivilege, &tp.Privileges[0].Luid);
      tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
      AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
      fOk = (GetLastError() == ERROR_SUCCESS);

      // Don't forget to close the token handle
      CloseHandle(hToken);
   }
   return(fOk);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void Dlg_OnCommand(HWND hWnd, int id) {
	char szError[ERR_BUFSIZE];

	switch (id) {
	case IDCANCEL:
		EndDialog(hWnd, id);
		break;

	case IDC_BUTTON_INJECT:
		WCHAR szLibFilename[MAX_PATH] = { 0 };
		PWSTR pFilename = NULL;

		// Get PID and DLL's name
		g_dwProcessId = GetDlgItemInt(hWnd, IDC_EDIT_PID, NULL, FALSE);
		UINT cb = GetDlgItemText(hWnd, IDC_EDIT_DLL, szLibFilename, _countof(szLibFilename));
		if (g_dwProcessId != 0 && cb > 0) {
			// 一定要使用 DLL 文件的绝对路径, 并将 DLL 放在本执行程序同目录下
			GetModuleFileName(NULL, g_szLibFilepath, MAX_PATH);
			pFilename = wcsrchr(g_szLibFilepath, '\\') + 1;
			lstrcpy(pFilename, szLibFilename);

			if (InjectLib(g_dwProcessId, g_szLibFilepath)) {
				if (EjectLib(g_dwProcessId, g_szLibFilepath)) {
					chMB("DLL Injection/Ejection succeeded!");
				}
			}
			else {
				sprintf(szError, "DLL Injection/Ejection failed: #%d", GetLastError());
				chERROR(szError);
			}
		}
		break;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK Dlg_Proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_COMMAND:
		Dlg_OnCommand(hWnd, LOWORD(wParam));
		break;
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow) {

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_INJLIB), NULL, Dlg_Proc);
	return 0;
}

////////////////////////////////////////// End of File /////////////////////////////////////////////////////////
