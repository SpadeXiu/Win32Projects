// ½« hook.dll ×¢Èëµ½ MessageBoxW.exe

#include <Windows.h>
#include <TlHelp32.h>

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

BOOL WINAPI GetProcessIdByName(PDWORD pdwProcessId, PWCHAR pszProcessName) {
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe = { sizeof(pe) };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) { return FALSE; }

	BOOL bMore = Process32First(hSnapshot, &pe);
	for (;bMore;bMore = Process32Next(hSnapshot, &pe)) {
		if (!lstrcmpi(pszProcessName, pe.szExeFile)) {
			*pdwProcessId = pe.th32ProcessID;
			break;
		}
	}
	CloseHandle(hSnapshot);
	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int) {
	DWORD dwProcessId;
	PWCHAR pszProcessName = TEXT("MessageBoxW.exe");
	PWCHAR pszLibFile = TEXT("hook.dll");

	// Get Process ID of "MessageBoxW.exe"
	if (!GetProcessIdByName(&dwProcessId, pszProcessName)) {
		MessageBox(NULL, TEXT("LoadLibrary Error"), TEXT("ERROR"), MB_ICONERROR);
		return EXIT_FAILURE;
	}

	// Inject it!
	if (InjectLib(dwProcessId, pszLibFile)) {
		if (EjectLib(dwProcessId, pszLibFile)) {
			MessageBox(NULL, TEXT("DLL Injection/Ejection succeeded!"), TEXT("ERROR"), MB_OK);
			return EXIT_SUCCESS;
		}
	}
	MessageBox(NULL, TEXT("DLL Injection/Ejection failed!"), TEXT("ERROR"), MB_ICONERROR);
	return EXIT_FAILURE;
}

///////////////////////////////////////////// End Of File /////////////////////////////////////////////////////
