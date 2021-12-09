#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "hook.h"
#include "../Include/Common.h"

struct HookEntry {
  PCSTR pszOrigProc;
  PCSTR pszOrigLib;
  PCSTR pszNewProc;
} entries[] = {
  //{ "CreateFileW", "Kernel32.DLL", "MyCreateFileW" },
  //{ "CreateFileA", "Kernel32.DLL", "MyCreateFileA" },
  //{ "ShellExecuteA", "Shell32.DLL", "MyShellExecuteA" },
  //{ "ShellExecuteW", "Shell32.DLL", "MyShellExecuteW" },
  //{ "HeapAlloc", "Kernel32.DLL", "MyHeapAlloc" }, // Hook HeapAlloc 会导致进程崩溃, 不知道为什么
  { "VirtualAlloc", "Kernel32.DLL", "MyVirtualAlloc" },
  { "VirtualFree", "Kernel32.DLL", "MyVirtualFree" },
};


BOOL WINAPI ReplaceIATEntryInOneMod(
  PCSTR pszCalleeModName,
  PROC pfnOrig,
  PROC pfnNew,
  HMODULE hModCaller) {
  ULONG ulSize;
  PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

  pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
      hModCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

  if (pImportDesc == NULL)
    return FALSE;  // This module has no import section or is no longer loaded

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
) {
  BOOL bSuccess = FALSE;
  char szMessage[BUF_SIZE] = { 0 };
  char szModulePath[MAX_PATH] = { 0 };

  HMODULE hToolMod = GetModuleHandle(TEXT("Tool.DLL"));
  if (hToolMod == NULL) {
    return FALSE;
  }

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
  if (hSnapshot == INVALID_HANDLE_VALUE) {
    MessageBox(0, TEXT("5"), TEXT("Error"), MB_ICONERROR);
    return FALSE;
  }

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
  if (hLogFile == INVALID_HANDLE_VALUE) {
    MessageBox(0, TEXT("6"), TEXT("Error"), MB_ICONERROR);
    return FALSE;
  }

  MODULEENTRY32 me = { sizeof(me) };
  BOOL bMore = Module32First(hSnapshot, &me);
  for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
    // NOTE: we don't hook functions in Tool.DLL
    if (me.hModule != hToolMod) {
      BOOL b = ReplaceIATEntryInOneMod(pszCalleeModName, pfnOrig, pfnNew, me.hModule);
      bSuccess |= b;

      // Record information if operation succeeds.
      if (b == TRUE) {
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

  if (!bSuccess)
    MessageBox(0, TEXT("7"), TEXT("Error"), MB_ICONERROR);

  return bSuccess;
}


BOOL WINAPI HookApi(
  PCSTR pszOrigProc,
  PCSTR pszOrigLib,
  PCSTR pszNewProc,
  PCSTR pszNewLib,
  HMODULE hModCaller
) {
  PROC pfnOrig, pfnNew;

  // Get function address which needs to be hooked.
  pfnOrig = GetProcAddress(GetModuleHandleA(pszOrigLib), pszOrigProc);
  if (pfnOrig == NULL) {
    MessageBox(0, TEXT("1"), TEXT("Error"), MB_ICONERROR);
    return FALSE;
  }

  // Load DLL which exports `pszNewProc`.
  HMODULE hLibInst = LoadLibraryA(pszNewLib);
  if (hLibInst == NULL) {
    MessageBox(0, TEXT("2"), TEXT("Error"), MB_ICONERROR);
    return FALSE;
  }

  // Get function address used to replace `pszOrigProc`.
  pfnNew = (PROC)GetProcAddress(hLibInst, pszNewProc);
  if (pfnNew == NULL) {
    MessageBox(0, TEXT("3"), TEXT("Error"), MB_ICONERROR);
    return FALSE;
  }

  // Hook API
  if (!ReplaceIATEntryInAllMods(pszOrigLib, pfnOrig, pfnNew, pszOrigProc)) {
    MessageBox(0, TEXT("4"), TEXT("Error"), MB_ICONERROR);
    return FALSE;
  }

  return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hInstanceDll, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH: // DLL loaded
      // Get main mudule handle of the caller's process.
      //HMODULE hModCaller = GetMainModuleHandleOfProcess(GetCurrentProcessId());
      HMODULE hModCaller = GetModuleHandle(NULL);
      if (hModCaller == NULL) {
        MessageBox(NULL, TEXT("GetModuleHandle Error"), TEXT("ERROR"), MB_ICONERROR);
        return FALSE;
      }

      // Get absolute path of Tool.DLL
      WCHAR wszLibFilePath[MAX_PATH] = { 0 };
      char szLibFilePath[MAX_PATH] = { 0 };
      PWCHAR pFileName = NULL;
      if (!GetProcessPathByName(TEXT("Monitor.exe"), wszLibFilePath)) {
        return FALSE;
      }
      pFileName = wcsrchr(wszLibFilePath, '\\') + 1;
      lstrcpy(pFileName, TEXT("Tool.DLL"));
      sprintf(szLibFilePath, "%ws", wszLibFilePath);

      for (int i = 0; i < _countof(entries); i++) {
        BOOL bOk = HookApi(entries[i].pszOrigProc, entries[i].pszOrigLib, entries[i].pszNewProc, szLibFilePath, hModCaller);
        char text[100] = { 0 };
        if (bOk) {
          sprintf(text, "API Hook \"%s\" succeeded!", entries[i].pszOrigProc);
          MessageBoxA(0, text, "Sucess", MB_OK);
        } else {
          sprintf(text, "API Hook \"%s\" failed!", entries[i].pszOrigProc);
          MessageBoxA(0, text, "Error", MB_ICONERROR);
        }
      }

      break;
  }
  return TRUE;
}
