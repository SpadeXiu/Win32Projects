#ifndef READ_PROCESS_MEMORY_H
#define READ_PROCESS_MEMORY_H

#include <ntddk.h>

#define OFFSET_CURRENT_THREAD		0x124
#define OFFSET_APC_STATE			0X40
#define OFFSET_PROCESS				0x10
#define OFFSET_DIR_TABLE_BASE		0x18
#define OFFSET_PID					0xb4
#define OFFSET_PROCESS_LINK			0xb8
#define OFFSET_IMAGE_FILENAME		0x16c

#define DEVICE_NAME 	   L"\\Device\\readprocessmemory"
#define DEVICE_SYMBOL_NAME L"\\??\\symlink_readprocessmemory"

#define MAX_BUFFER_LEN	512
#define MEM_TAG			'MYTG'


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

#endif // READ_PROCESS_MEMORY_H
