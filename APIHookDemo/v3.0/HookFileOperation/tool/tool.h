#ifndef TOOL_H
#define TOOL_H

#include <Windows.h>
#include <TlHelp32.h>

#define BUF_SIZE 512
#define DEVICE_NAME_LEN 4

#define LOG_FILE TEXT("C:\\Users\\len\\Desktop\\log.txt")

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
	_In_opt_	HWND   hwnd,
	_In_		LPCSTR lpOperation,
	_In_opt_	LPCSTR lpFile,
	_In_opt_	LPCSTR lpParameters,
	_In_opt_	LPCSTR lpDirectory,
	_In_		INT    nShowCmd
	);

HINSTANCE WINAPI MyShellExecuteW(
	_In_opt_	HWND	hwnd,
	_In_		LPCWSTR lpOperation,
	_In_opt_	LPCWSTR lpFile,
	_In_opt_	LPCWSTR lpParameters,
	_In_opt_	LPCWSTR lpDirectory,
	_In_		INT		nShowCmd
	);

BOOL WINAPI GetFilePathByHandle(
	_In_		HANDLE		 hFile,
	_Out_		PWSTR		 pszFilePath,
	_In_		UINT		 uBufferLen
	);

#endif // TOOL_H
