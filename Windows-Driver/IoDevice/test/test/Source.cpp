#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <conio.h>

#define MAX_BUFFER_LEN 512

#define DEVICE_NAME L"\\\\.\\symlink_iodevice"

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

void exit(HANDLE hDevice)
{
	if (hDevice != NULL || hDevice != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hDevice);
		printf("\nClose device successfully!");
	}

	printf("\nPress any key to exit...");
	_getch();
}

int main()
{
	HANDLE hDevice = NULL;

	hDevice = CreateFile(
		DEVICE_NAME,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_SYSTEM,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("Open Device Error: #%d\n", GetLastError());
		exit(hDevice);
		return EXIT_FAILURE;
	}
	else
	{
		printf("Open Device Successfully!\n");
	}

	DWORD cb = 0;

	//
	// Test: User app sends data to kenerl driver
	//

	printf("\nTest sending data. user app -> kernel driver\n");

	// case-1 - 发送数据的长度小于允许的最大缓冲区长度，
	//			DeviceIoControl 应该成功，返回 非(0)

	char msg[] = "Data from user app...\r\n";
	if ( 0 != DeviceIoControl(hDevice, DEVICE_SEND_DATA, msg, strlen(msg) + 1, 
		NULL, 0, &cb, NULL) )
	{
		printf("TEST-1 passed\n");
	}
	else
	{
		printf("TEST-1 failed - DeviceIoControl Error: #%d\n", GetLastError());
	}

	// case-2 - 发送数据的长度比允许的最大缓冲区长度大 1 字节，
	//			DeviceIoControl 应该失败，返回 (0)

	char pInBuffer[MAX_BUFFER_LEN + 1];
	memset(pInBuffer, 'A', sizeof(pInBuffer));
	pInBuffer[sizeof(pInBuffer) - 1] = '\0';
	cb = 0;
	if ( 0 == DeviceIoControl(hDevice, DEVICE_SEND_DATA, pInBuffer, strlen(pInBuffer) + 1,
		NULL, 0, &cb, NULL) )
	{
		printf("TEST-2 passed\n");
	}
	else
	{
		printf("TEST-2 failed\n");
	}

	// case-3 - 发送数据的长度比允许的最大缓冲区长度小 1 字节，
	//			DeviceIoControl 应该成功，返回 非(0)

	char pInBuffer2[MAX_BUFFER_LEN - 1];
	memset(pInBuffer2, 'B', sizeof(pInBuffer2));
	pInBuffer2[sizeof(pInBuffer2) - 1] = '\0';
	cb = 0;
	if (0 != DeviceIoControl(hDevice, DEVICE_SEND_DATA, pInBuffer2, strlen(pInBuffer2) + 1,
		NULL, 0, &cb, NULL))
	{
		printf("TEST-3 passed\n");
	}
	else
	{
		printf("TEST-3 failed\n");
	}

	// case-4 - 发送数据的长度等于允许的最大缓冲区,
	//			DeviceIoControl 应该成功，返回 非(0)

	char pInBuffer3[MAX_BUFFER_LEN - 1];
	memset(pInBuffer3, 'C', sizeof(pInBuffer3));
	pInBuffer3[sizeof(pInBuffer3) - 1] = '\0';
	cb = 0;
	if (0 != DeviceIoControl(hDevice, DEVICE_SEND_DATA, pInBuffer3, strlen(pInBuffer3) + 1,
		NULL, 0, &cb, NULL))
	{
		printf("TEST-4 passed\n");
	}
	else
	{
		printf("TEST-4 failed\n");
	}

	//
	// Test: User app receives data from kernel driver
	//

	printf("\nTest receiving data. user app <- kernel driver\n");

	// case-5 - 使用长度为 MAX_BUFFER_LEN 的缓冲区接收数据，接收到的数据的长度不超过 MAX_BUFFER_LEN,
	//			DeviceIoControl 应该成功，返回 非(0)

	printf("\nTEST-5 running...\n");

	char pOutBuffer[MAX_BUFFER_LEN] = { 0 };
	cb = 0;
	if ( 0 != DeviceIoControl(hDevice, DEVICE_RECV_DATA, NULL, 0,
		pOutBuffer, sizeof(pOutBuffer), &cb, NULL) )
	{
		printf("Received data length: %d\n", cb);
		printf("Data received from driver>> %s", pOutBuffer);
		printf("\nTEST-5 passed\n");
	}
	else
	{
		printf("TEST-5 failed - DeviceIoControl Error: #%d\n", GetLastError());
	}

	// case-6 - 使用较小的缓冲区接收数据，接收到的数据的长度会超过该长度,
	//			DeviceIoControl 应该失败，返回 (0)

	printf("\nTEST-6 running...\n");

	char pOutBuffer2[10] = { 0 };
	cb = 0;
	if (0 == DeviceIoControl(hDevice, DEVICE_RECV_DATA, NULL, 0,
		pOutBuffer2, sizeof(pOutBuffer2), &cb, NULL))
	{
		printf("Received data length: %d\n", cb);
		printf("Data received from driver>> %s", pOutBuffer2);
		printf("\nTEST-6 passed\n");
	}
	else
	{
		printf("TEST-6 failed - DeviceIoControl Error: #%d\n", GetLastError());
	}

	exit(hDevice);
	return EXIT_SUCCESS;
}
