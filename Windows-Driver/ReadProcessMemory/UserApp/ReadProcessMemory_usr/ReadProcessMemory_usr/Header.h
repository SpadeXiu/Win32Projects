#ifndef HEADER_H
#define HEADER_H

#include <Windows.h>

#define DEVICE_NAME L"\\??\\symlink_readprocessmemory"

// @param `Function` 0~0x7ff are reserved by Microsoft
#define DEVICE_SEND_DATA \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x800, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#define DEVICE_RECV_DATA \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x801, \
					METHOD_BUFFERED, \
					FILE_READ_DATA)

BOOL WINAPI MyReadProcessMemory(
	_In_ DWORD dwProcessId,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T * lpNumberOfBytesRead
);

#endif // HEADER_H
