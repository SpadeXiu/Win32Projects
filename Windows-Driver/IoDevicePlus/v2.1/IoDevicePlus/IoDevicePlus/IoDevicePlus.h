#ifndef IODEVICE_PLUS_H
#define IODEVICE_PLUS_H

#include <ntddk.h>

#define MEM_NAME_LEN		16
#define CONNECT_SUCCESS		1
#define CONNECT_ERROR		0
#define BLOCKING			0x100
#define NON_BLOCKING		0x101

typedef struct _MEMORY_TABLE {
	LIST_ENTRY	ListEntry;
	CHAR		Name[MEM_NAME_LEN];
	ULONG		ServerId;
	ULONG		ClientId;
	ULONG		ConnectStatus; // the status of connection
	ULONG		ClientBlockStatus;
	ULONG		ServerBlockStatus;
	PVOID		MemBase; // memory base of allocation
	ULONG		MemLength; // memory length of allocaion
	ULONG		AvailableLength; // available length of allocated memory
} MEMORY_TABLE, *PMEMORY_TABLE;

#define DEVICE_NAME 	   L"\\Device\\iodevice_plus"
#define DEVICE_SYMBOL_NAME L"\\??\\symlink_iodevice_plus"

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
					FILE_READ_DATA | FILE_WRITE_DATA)

#define DEVICE_MEM_ALLOC \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x902, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#define DEVICE_MEM_FREE \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x903, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#define DEVICE_OPEN_MEM \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x904, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#define DEVICE_CONNECT \
	(ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, \
					0x905, \
					METHOD_BUFFERED, \
					FILE_WRITE_DATA)

#endif // IODEVICE_PLUS_H
