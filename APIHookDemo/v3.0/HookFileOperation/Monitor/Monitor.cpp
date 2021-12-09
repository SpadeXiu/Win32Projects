#define _CRT_SECURE_NO_WARNINGS
#include "Monitor.h"
#include <stdio.h>

Monitor::Monitor(DWORD dwProcessId, PCWSTR pszLibFile) {
  m_dwProcessId = dwProcessId;
  if (pszLibFile != NULL) {
    lstrcpy(m_szLibFile, pszLibFile);
  }
}

BOOL Monitor::InjectLib() {
  BOOL bSuccess = FALSE;
  HANDLE hProcess = NULL;
  HANDLE hThread = NULL;
  PWSTR pszLibFileRemote = NULL;

  __try {
    // Get a handle of the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwProcessId);
    if (hProcess == NULL)
      __leave;

    // Calculate the number of bytes needed for DLL's pathname
    int cch = lstrlenW(m_szLibFile) + 1;
    int cb = cch * sizeof(wchar_t);

    // Allocate space in the remote process for DLL's pathname
    pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);
    if (pszLibFileRemote == NULL)
      __leave;

    // Copy the DLL's pathname to the remote process' address space
    if (!WriteProcessMemory(hProcess, (LPVOID)pszLibFileRemote, m_szLibFile, cb, NULL))
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

    bSuccess = TRUE; // Eveything executed successfully
  } __finally {
    if (pszLibFileRemote != NULL)
      VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

    if (hThread != NULL)
      CloseHandle(hThread);

    if (hProcess != NULL)
      CloseHandle(hProcess);
  }

  return bSuccess;
}

BOOL Monitor::EjectLib() {
  BOOL bSuccess = FALSE;
  HANDLE hSnapshot = NULL;
  HANDLE hProcess = NULL;
  HANDLE hThread = NULL;

  __try {
    // Grab a snapshot of the process
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE)
      __leave;

    // Get the MODULE of the injected library
    MODULEENTRY32 me = { sizeof(me) };
    BOOL bFound = FALSE;
    BOOL bMoreMods = Module32First(hSnapshot, &me);
    for (; bMoreMods; bMoreMods = Module32Next(hSnapshot, &me)) {
      bFound = (lstrcmpi(me.szModule, m_szLibFile) == 0 ||
          lstrcmpi(me.szExePath, m_szLibFile) == 0);
      if (bFound) break;
    }
    if (!bFound) __leave;

    // Get the handle of the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwProcessId);
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

    bSuccess = TRUE; // Eveything executed successfully
  } __finally {
    if (hSnapshot != NULL)
      CloseHandle(hSnapshot);

    if (hThread != NULL)
      CloseHandle(hThread);

    if (hProcess != NULL)
      CloseHandle(hProcess);
  }

  return bSuccess;
}

BOOL Monitor::EnablePrivilege(LPWSTR privilageName) {
  HANDLE hToken;
  TOKEN_PRIVILEGES tp;
  BOOL bSuccess = FALSE;

  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
    tp.PrivilegeCount = 1;

    if (!LookupPrivilegeValue(NULL, privilageName, &tp.Privileges[0].Luid)) {
      printf("Can't lookup privilege value.\n");
    }

    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
      printf("Can't adjust privilege value.\n");
    }

    bSuccess = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
  }
  return bSuccess;
}
