#ifndef IOCTL_H
#define IOCTL_H

#include <Windows.h>

#define DEVICE_NAME		L"\\\\.\\symlink_iodevice_plus"

#define MAX_BUFFER_LEN	512
#define MEM_TAG			'MYTG'

// @param `Function` 0~0x7ff are reserved by Microsoft
#define DEVICE_SEND_DATA \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x900, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#define DEVICE_RECV_DATA \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x901, \
					METHOD_BUFFERED, \
					FILE_READ_DATA)

#define DEVICE_MEM_ALLOC \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x902, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)


HANDLE OpenSharedMemory();
HANDLE CreateSharedMemory(DWORD uSize);
BOOL ReadSharedMemory(HANDLE hDevice, PVOID pBuffer, DWORD nSize, PDWORD pBytesRead);
BOOL WriteSharedMemory(HANDLE hDevice, PVOID pBuffer, DWORD nSize, PDWORD pBytesWritten);
VOID DestorySharedMemory(HANDLE hDevice);

#endif // IOCTL_H
