#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include "tool.h"
#include "../Include/Common.h"

HANDLE WINAPI MyCreateFileW(
  _In_     LPCTSTR               lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };
  HANDLE hFile = NULL;

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将文件操作信息记入日志
  // NOTE: 文件操作只能直接使用系统 API，否则会出错，因为目标进程
  //		 中除了 Tool.DLL 外的所有模块中的 API 都被 Hook 住了.
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_CreateFileW"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"CreateFileW\", FileName: %ws, DesiredAccess: 0x%.8x\r\n",
      szTime, szProcessPath, dwProcessId, lpFileName, dwDesiredAccess);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  hFile = CreateFileW(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile
    );

  return hFile;
}


HANDLE WINAPI MyCreateFileA(
  _In_     LPCSTR                lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };
  HANDLE hFile = NULL;

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将文件操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_CreateFileA"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"CreateFileA\", FileName: %s, DesiredAccess: 0x%.8x\r\n",
      szTime, szProcessPath, dwProcessId, lpFileName, dwDesiredAccess);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  hFile = CreateFileA(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile
    );

  return hFile;
}

BOOL WINAPI MyReadFile(
  _In_        HANDLE       hFile,
  _Out_       LPVOID       lpBuffer,
  _In_        DWORD        nNumberOfBytesToRead,
  _Out_opt_   LPDWORD      lpNumberOfBytesRead,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  WCHAR szFilePath[MAX_PATH] = { 0 };
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将文件操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_ReadFile"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    GetFilePathByHandle(hFile, szFilePath, sizeof(szFilePath));

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"ReadFile\", FileName: %ws\r\n",
      szTime, szProcessPath, dwProcessId, szFilePath);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  return ReadFile(hFile,
      lpBuffer,
      nNumberOfBytesToRead,
      lpNumberOfBytesRead,
      lpOverlapped);
}

HINSTANCE WINAPI MyShellExecuteA(
  _In_opt_	HWND   hwnd,
  _In_		  LPCSTR lpOperation,
  _In_opt_	LPCSTR lpFile,
  _In_opt_	LPCSTR lpParameters,
  _In_opt_	LPCSTR lpDirectory,
  _In_		  INT    nShowCmd
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };
  HANDLE hFile = NULL;

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_ShellExecuteA"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"ShellExecuteA\", Operation: %s, File: %s\r\n",
      szTime, szProcessPath, dwProcessId, lpOperation, lpFile);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  return ShellExecuteA(hwnd,
      lpOperation,
      lpFile,
      lpParameters,
      lpDirectory,
      nShowCmd);
}

HINSTANCE WINAPI MyShellExecuteW(
  _In_opt_	HWND	  hwnd,
  _In_		  LPCWSTR lpOperation,
  _In_opt_	LPCWSTR lpFile,
  _In_opt_	LPCWSTR lpParameters,
  _In_opt_	LPCWSTR lpDirectory,
  _In_		  INT		  nShowCmd
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };
  HANDLE hFile = NULL;

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_ShellExecuteW"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"ShellExecuteW\", Operation: %ws, File: %ws\r\n",
      szTime, szProcessPath, dwProcessId, lpOperation, lpFile);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  return ShellExecuteW(hwnd,
      lpOperation,
      lpFile,
      lpParameters,
      lpDirectory,
      nShowCmd);
}

BOOL WINAPI GetFilePathByHandle(
  _In_		HANDLE	 hFile,
  _Out_		PWSTR		 pszFilePath,
  _In_		UINT		 uBufferLen
) {
  DWORD dwFileSize = GetFileSize(hFile, NULL);

  HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, dwFileSize, NULL);
  if (hFileMap == NULL) {
    return FALSE;
  }

  LPVOID pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, dwFileSize);
  if (pMem == NULL) {
    return FALSE;
  }

  DWORD bSuccess;
  bSuccess = GetMappedFileName(GetCurrentProcess(),
      pMem,
      pszFilePath, // 获得设备名形式的文件路径
      uBufferLen);
  if (bSuccess == 0) {
    return FALSE;
  }

  // 获取计算机中的驱动器名 (磁盘盘符)
  WCHAR drvBuf[BUF_SIZE];
  bSuccess = GetLogicalDriveStrings(sizeof(drvBuf) - 1, drvBuf);
  if (bSuccess == 0) {
    return FALSE;
  }

  WCHAR szDeviceName[DEVICE_NAME_LEN];
  WCHAR szTargetPath[MAX_PATH];
  BOOL bFound = FALSE;
  for (PWSTR p = drvBuf; *p && !bFound; p += DEVICE_NAME_LEN) {
    lstrcpy(szDeviceName, p);
    szDeviceName[DEVICE_NAME_LEN - 2] = 0; // 去掉驱动器名末尾的 '\'
    // 获取设备名 szDeviceName 对应的驱动器名 szTargetPath
    if (!QueryDosDevice(szDeviceName, szTargetPath, sizeof(szTargetPath))) {
      return FALSE;
    }

    int nameLen = lstrlen(szTargetPath);
    if (!wcsncmp(pszFilePath, szTargetPath, nameLen)) {
      PWSTR pStr = pszFilePath + nameLen;
      lstrcpy(pszFilePath, szDeviceName);
      lstrcpy(pszFilePath + lstrlen(szDeviceName), pStr);
    }
  }

  UnmapViewOfFile(pMem);
  CloseHandle(hFileMap);

  return TRUE;
}

LPVOID WINAPI MyHeapAlloc(
  _In_    HANDLE   hHeap,
  _In_    DWORD    dwFlags,
  _In_    SIZE_T   dwBytes
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_HeapAlloc.txt"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"HeapAlloc\", MemSize: %d\r\n",
      szTime, szProcessPath, dwProcessId, dwBytes);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  return HeapAlloc(hHeap, dwFlags, dwBytes);
}

LPVOID WINAPI MyVirtualAlloc(
  _In_opt_  LPVOID  lpAddress,
  _In_      SIZE_T  dwSize,
  _In_      DWORD   flAllocationType,
  _In_      DWORD   flProtect
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_VirtualAlloc.txt"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"VirtualAlloc\", Address: %p, MemSize: %d\r\n",
      szTime, szProcessPath, dwProcessId, lpAddress, dwSize);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI MyVirtualFree(
  _In_    LPVOID  lpAddress,
  _In_    SIZE_T  dwSize,
  _In_    DWORD   dwFreeType
) {
  DWORD dwProcessId = 0;
  WCHAR szProcessPath[MAX_PATH] = { 0 };
  SYSTEMTIME st;
  char szMessage[BUF_SIZE] = { 0 };
  char szTime[BUF_SIZE] = { 0 };

  // 获取目标进程的 PID 和执行文件全路径
  dwProcessId = GetCurrentProcessId();
  GetProcessPathById(dwProcessId, szProcessPath);

  // 将操作信息记入日志
  HANDLE hLogFile = CreateFile(
      TEXT("LOG_VirtualFree.txt"),
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );
  if (hLogFile != INVALID_HANDLE_VALUE) {
    // Information will be attached to the file.
    SetFilePointer(hLogFile, 0, NULL, FILE_END);

    GetLocalTime(&st);
    sprintf(szTime, "%d/%d/%d %d:%d:%d",
      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    sprintf(szMessage, "#%s# Process [%ws]--[%d] is calling \"VirtualFree\", Address: %p, MemSize: %d\r\n",
      szTime, szProcessPath, dwProcessId, lpAddress, dwSize);

    DWORD dw;
    WriteFile(hLogFile, szMessage, strlen(szMessage), &dw, NULL);
    CloseHandle(hLogFile);
  }

  return VirtualFree(lpAddress, dwSize, dwFreeType);
}