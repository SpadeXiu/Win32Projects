#ifndef TOOL_H
#define TOOL_H

#include <Windows.h>
#include <TlHelp32.h>

// 对于下面这些 WINAPI 声明的函数无法使用 DLL_EXPORT 正确导出, 应该在 Source.def 里导出
// #define DLL_EXPORT extern "C" __declspec(dllexport)

#define BUF_SIZE 512
#define DEVICE_NAME_LEN 4

#define LOG_FILE TEXT("log.txt")

HANDLE WINAPI MyCreateFileW(
  _In_     LPCTSTR               lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
);

HANDLE WINAPI MyCreateFileA(
  _In_     LPCSTR                lpFileName,
  _In_     DWORD                 dwDesiredAccess,
  _In_     DWORD                 dwShareMode,
  _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_     DWORD                 dwCreationDisposition,
  _In_     DWORD                 dwFlagsAndAttributes,
  _In_opt_ HANDLE                hTemplateFile
);

BOOL WINAPI MyReadFile(
  _In_        HANDLE       hFile,
  _Out_       LPVOID       lpBuffer,
  _In_        DWORD        nNumberOfBytesToRead,
  _Out_opt_   LPDWORD      lpNumberOfBytesRead,
  _Inout_opt_ LPOVERLAPPED lpOverlapped
);

HINSTANCE WINAPI MyShellExecuteA(
  _In_opt_  HWND    hwnd,
  _In_      LPCSTR  lpOperation,
  _In_opt_  PCSTR   lpFile,
  _In_opt_  PCSTR   lpParameters,
  _In_opt_  PCSTR   lpDirectory,
  _In_      INT     nShowCmd
);

HINSTANCE WINAPI MyShellExecuteW(
  _In_opt_  HWND     hwnd,
  _In_      LPCWSTR  lpOperation,
  _In_opt_  LPCWSTR  lpFile,
  _In_opt_  LPCWSTR  lpParameters,
  _In_opt_  LPCWSTR  lpDirectory,
  _In_      INT      nShowCmd
);

BOOL WINAPI GetFilePathByHandle(
  _In_		HANDLE   hFile,
  _Out_		PWSTR    pszFilePath,
  _In_		UINT     uBufferLen
);

LPVOID WINAPI MyHeapAlloc(
  _In_    HANDLE   hHeap,
  _In_    DWORD    dwFlags,
  _In_    SIZE_T   dwBytes
);

LPVOID WINAPI MyVirtualAlloc(
  _In_opt_  LPVOID  lpAddress,
  _In_      SIZE_T  dwSize,
  _In_      DWORD   flAllocationType,
  _In_      DWORD   flProtect
);

BOOL WINAPI MyVirtualFree(
  _In_    LPVOID  lpAddress,
  _In_    SIZE_T  dwSize,
  _In_    DWORD   dwFreeType
);

#endif // TOOL_H
