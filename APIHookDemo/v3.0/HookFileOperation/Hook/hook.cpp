#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "hook.h"
#include "../Include/Common.h"


BOOL WINAPI ReplaceIATEntryInOneMod(
	PCSTR pszCalleeModName,
	PROC pfnOrig,
	PROC pfnNew, 
	HMODULE hModCaller)
{
	ULONG ulSize;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
		hModCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

	if (pImportDesc == NULL)
		return FALSE;  // This module has no import section or is no longer loaded

	// Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszModName = (PSTR)((PBYTE)hModCaller + pImportDesc->Name);
		if (lstrcmpiA(pszModName, pszCalleeModName) == 0)
		{
			// Get caller's import address table (IAT) for the callee's functions
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
				((PBYTE)hModCaller + pImportDesc->FirstThunk);

			// Replace original function address with new function address
			for (; pThunk->u1.Function; pThunk++)
			{
				// Is this the function we're looking for?
				BOOL bFound = ((PROC)pThunk->u1.Function == pfnOrig);
				if (bFound)
				{
					// Get the address of the function address
					PROC* ppfn = (PROC*)&pThunk->u1.Function;

					DWORD dwOldProtect;
					if (VirtualProtect(ppfn, sizeof(pfnNew), PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew, sizeof(pfnNew), NULL);
						VirtualProtect(ppfn, sizeof(ppfn), dwOldProtect, &dwOldProtect);
						return TRUE;  // We did it, get out
					}
				}
			}  // Each import section is parsed until the right entry is found and patched
		}
	}
	return FALSE;
}

BOOL WINAPI ReplaceIATEntryInAllMods(
	PCSTR pszCalleeModName,
	PROC pfnOrig,
	PROC pfnNew,
	PCSTR pszOrigProc
	)
{
	BOOL bSuccess = FALSE;
	char szMessage[BUF_SIZE] = { 0 };
	char szModulePath[MAX_PATH] = { 0 };

	HMODULE hToolMod = GetModuleHandle(TEXT("Tool.DLL"));
	if (hToolMod == NULL)
		return FALSE;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	// Create log file.
	HANDLE hLogFile = CreateFile(
		HOOK_LOG_FILE,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);
	if (hLogFile == INVALID_HANDLE_VALUE)
		return FALSE;

	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		// NOTE: we don't hook functions in Tool.DLL
		if (me.hModule != hToolMod)
		{
			BOOL b = ReplaceIATEntryInOneMod(pszCalleeModName,
				pfnOrig, pfnNew, me.hModule);

			bSuccess |= b;

			// Record information if operation succeeds.
			if (b == TRUE)
			{
				GetModuleFileNameA(me.hModule, szModulePath, MAX_PATH);
				sprintf(szMessage, "[Hook] API: %s, Module: %s\r\n", pszOrigProc, szModulePath);

				// Information will be attached to the file.
				DWORD dw;
				SetFilePointer(hLogFile, 0, NULL, FILE_END);
				WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
			}
		}
	}

	CloseHandle(hSnapshot);
	CloseHandle(hLogFile);

	return bSuccess;
}


BOOL WINAPI HookApi(
	PCSTR pszOrigProc,
	PCSTR pszOrigLib,
	PCSTR pszNewProc,
	PCSTR pszNewLib,
	HMODULE hModCaller
	)
{
	PROC pfnOrig, pfnNew;

	// Get function address which needs to be hooked.
	pfnOrig = GetProcAddress(GetModuleHandleA(pszOrigLib), pszOrigProc);
	if (pfnOrig == NULL){ return FALSE; }

	// Load DLL which exports `pszNewProc`.
	HMODULE hLibInst = LoadLibraryA(pszNewLib);
	if (hLibInst == NULL){ return FALSE; }

	// Get function address used to replace `pszOrigProc`.
	pfnNew = (PROC)GetProcAddress(hLibInst, pszNewProc);
	if (pfnNew == NULL){ return FALSE; }

	// Hook API
	if (!ReplaceIATEntryInAllMods(pszOrigLib, pfnOrig, pfnNew, pszOrigProc))
		return FALSE;

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hInstanceDll, DWORD fdwReason, LPVOID lpReserved) 
{
	switch (fdwReason) 
	{
	case DLL_PROCESS_ATTACH: // DLL loaded
		// Get main mudule handle of the caller's process.
		//HMODULE hModCaller = GetMainModuleHandleOfProcess(GetCurrentProcessId());
		HMODULE hModCaller = GetModuleHandle(NULL);
		if (hModCaller == NULL) 
		{
			MessageBox(NULL, TEXT("GetModuleHandle Error"), TEXT("ERROR"), MB_ICONERROR);
			return FALSE;
		}

		// Get absolute path of Tool.DLL
		WCHAR wszLibFilePath[MAX_PATH] = { 0 };
		char szLibFilePath[MAX_PATH] = { 0 };
		PWCHAR pFileName = NULL;
		if (!GetProcessPathByName(TEXT("Monitor.exe"), wszLibFilePath))
		{ 
			return FALSE; 
		}
		pFileName = wcsrchr(wszLibFilePath, '\\') + 1;
		lstrcpy(pFileName, TEXT("Tool.DLL"));
		sprintf(szLibFilePath, "%ws", wszLibFilePath);

		BOOL bSuccess = HookApi("CreateFileW", "Kernel32.DLL",
			"MyCreateFileW", szLibFilePath, hModCaller);
		if (bSuccess)
		{
			MessageBox(0, TEXT("API Hook \"CreateFileW\" succeeded!"), TEXT("Success"), MB_OK);
		}
		else
		{
			MessageBox(0, TEXT("API Hook \"CreateFileW\" failed!"), TEXT("Error"), MB_ICONERROR);
		}

		bSuccess = HookApi("CreateFileA", "Kernel32.DLL",
			"MyCreateFileA", szLibFilePath, hModCaller);
		if (bSuccess)
		{
			MessageBox(0, TEXT("API Hook \"CreateFileA\" succeeded!"), TEXT("Success"), MB_OK);
		}
		else
		{
			MessageBox(0, TEXT("API Hook \"CreateFileA\" failed!"), TEXT("Error"), MB_ICONERROR);
		}

		bSuccess = HookApi("ReadFile", "Kernel32.DLL",
			"MyReadFile", szLibFilePath, hModCaller);
		if (bSuccess)
		{
			MessageBox(0, TEXT("API Hook \"ReadFile\" succeeded!"), TEXT("Success"), MB_OK);
		}
		else
		{
			MessageBox(0, TEXT("API Hook \"ReadFile\" failed!"), TEXT("Error"), MB_ICONERROR);
		}

		bSuccess = HookApi("ShellExecuteA", "Shell32.DLL",
			"MyShellExecuteA", szLibFilePath, hModCaller);
		if (bSuccess)
		{
			MessageBox(0, TEXT("API Hook \"ShellExecuteA\" succeeded!"), TEXT("Success"), MB_OK);
		}
		else
		{
			MessageBox(0, TEXT("API Hook \"ShellExecuteA\" failed!"), TEXT("Error"), MB_ICONERROR);
		}

		bSuccess = HookApi("ShellExecuteW", "Shell32.DLL",
			"MyShellExecuteW", szLibFilePath, hModCaller);
		if (bSuccess)
		{
			MessageBox(0, TEXT("API Hook \"ShellExecuteW\" succeeded!"), TEXT("Success"), MB_OK);
		}
		else
		{
			MessageBox(0, TEXT("API Hook \"ShellExecuteW\" failed!"), TEXT("Error"), MB_ICONERROR);
		}

		break;
	}
	return TRUE;
}
