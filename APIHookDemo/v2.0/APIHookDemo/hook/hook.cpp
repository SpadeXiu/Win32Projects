// hook.dll 一旦被加载，便会拦截加载者进程对 MessageBoxW 的调用，
// 并使用 spy.dll-SpyApiCalling 替换之.

#include <Windows.h>
#include <ImageHlp.h>
#include <TlHelp32.h>

#pragma comment(lib,"ImageHlp")

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

VOID WINAPI ReplaceIATEntryInOneMod(PCSTR pszCalleeModName, PROC pfnOrig, PROC pfnNew, HMODULE hModCaller) {
	ULONG ulSize;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
		hModCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

	if (pImportDesc == NULL)
		return;  // This module has no import section or is no longer loaded

				 // Find the import descriptor containing references to callee's functions
	for (; pImportDesc->Name; pImportDesc++) {
		PSTR pszModName = (PSTR)((PBYTE)hModCaller + pImportDesc->Name);
		if (lstrcmpiA(pszModName, pszCalleeModName) == 0) {

			// Get caller's import address table (IAT) for the callee's functions
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
				((PBYTE)hModCaller + pImportDesc->FirstThunk);

			// Replace original function address with new function address
			for (; pThunk->u1.Function; pThunk++) {

				// Is this the function we're looking for?
				BOOL bFound = ((PROC)pThunk->u1.Function == pfnOrig);
				if (bFound) {
					// Get the address of the function address
					PROC* ppfn = (PROC*)&pThunk->u1.Function;

					DWORD dwOldProtect;
					if (VirtualProtect(ppfn, sizeof(pfnNew), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
						WriteProcessMemory(GetCurrentProcess(), ppfn, &pfnNew, sizeof(pfnNew), NULL);
					}
					return;  // We did it, get out
				}
			}
		}  // Each import section is parsed until the right entry is found and patched
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL GetProcessName(DWORD dwProcessId, LPWSTR lpszProcessname) {
	BOOL bOk = FALSE;
	HANDLE hSnapshot = NULL;
	MODULEENTRY32 me = { sizeof(me) };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) { return FALSE; }

	BOOL bMoreMods = Module32First(hSnapshot, &me);
	for (;bMoreMods;bMoreMods = Module32Next(hSnapshot, &me)) {
		if (dwProcessId == me.th32ProcessID) {
			lstrcpy(lpszProcessname, me.szModule);
			bOk = TRUE;
			break;
		}
	}
	CloseHandle(hSnapshot);
	return bOk;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// 进程的主模块通常是进程对应的exe程序文件.
// GetMainModuleHandleOfProcess 返回进程主模块的句柄
HMODULE WINAPI GetMainModuleHandleOfProcess(DWORD dwProcessId) {
	HANDLE hSnapshot = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	WCHAR szProcessName[MAX_PATH];

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) { return NULL; }

	if (!GetProcessName(dwProcessId, szProcessName)) { return NULL; }

	BOOL bMore = Module32First(hSnapshot, &me);
	for (;bMore;bMore = Module32Next(hSnapshot, &me)) {
		if (!lstrcmpi(szProcessName, me.szModule)) {
			CloseHandle(hSnapshot);
			return me.hModule;
		}
	}
	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hInstanceDll, DWORD fdwReason, LPVOID lpReserved) {
	PROC pfnOrig, pfnNew;
	HMODULE hModCaller;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH: // DLL loaded
		// Get main mudule handle of the caller's process.
		hModCaller = GetMainModuleHandleOfProcess(GetCurrentProcessId());
		if (hModCaller == NULL) {
			MessageBox(NULL, TEXT("GetModuleHandle Error"), TEXT("ERROR"), MB_ICONERROR);
			return FALSE;
		}

		// Get function address which needs to be hooked.
		pfnOrig = GetProcAddress(GetModuleHandle(TEXT("user32.dll")), "MessageBoxW");

		// Load spy.dll, which exports the function `SpyApiCalling`.
		HMODULE hInstLib = LoadLibrary(TEXT("spy.dll"));
		if (hInstLib == NULL) {
			MessageBox(NULL, TEXT("LoadLibrary Error"), TEXT("ERROR"), MB_ICONERROR);
			return FALSE;
		}

		// Get function address used to replace `MessageBoxW`.
		pfnNew = (PROC)GetProcAddress(hInstLib, "SpyApiCalling");
		if (pfnNew == NULL) {
			MessageBox(NULL, TEXT("GetProcAddress Error"), TEXT("ERROR"), MB_ICONERROR);
			return FALSE;
		}

		// do it!
		ReplaceIATEntryInOneMod("user32.dll", pfnOrig, pfnNew, hModCaller);
		break;
	}
	return TRUE;
}

///////////////////////////////////////////// End Of File /////////////////////////////////////////////////////
