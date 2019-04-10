#define _CRT_SECURE_NO_WARNINS

#include <Windows.h>
#include <stdio.h>
#include <ImageHlp.h>
#pragma comment(lib,"ImageHlp")

void ReplaceIATEntryInOneMod(PCSTR pszCalleeModName, PROC pfnOrig, PROC pfnNew, HMODULE hModCaller) {
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

int main() {
	PROC pfnOrig, pfnNew;
	HMODULE hModCaller, hInstLib;

	pfnOrig = GetProcAddress(GetModuleHandle(TEXT("user32.dll")), "MessageBoxW");

	hModCaller = GetModuleHandle(TEXT("APIHookDemo.exe")); // self-hook

	hInstLib = LoadLibrary(TEXT("spy.dll"));
	if (hInstLib == NULL) {
		printf("LoadLibraryA Error: %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	pfnNew = (PROC)GetProcAddress(hInstLib, "SpyApiCalling");
	if (pfnNew == NULL) {
		printf("GetProcAddress Error: %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	ReplaceIATEntryInOneMod("user32.dll", pfnOrig, pfnNew, hModCaller);

	MessageBoxW(0, TEXT("hello"), TEXT("test"), MB_OK);

	return EXIT_SUCCESS;
}