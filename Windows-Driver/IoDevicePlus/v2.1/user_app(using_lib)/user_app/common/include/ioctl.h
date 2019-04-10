#ifndef IOCTL_H
#define IOCTL_H

#define _CRT_SECURE_NO_WARNINGS

#define CONNECT_SUCCESS		1
#define CONNECT_ERROR		0

#include <Windows.h>


/**
 * @param	pszName		The unique name of "shared memory".
 * 
 * @return	A handle to "shared memory".
 */
HANDLE OpenSharedMemory(PSTR pszName);

/**
 * @param	hMemory		A handle to "shared memory".
 *
 * @return	A dword specified the status of connection.
 *
 * @brief	This function won't wait until a client connect to
 *			"shared memory" by calling `OpenSharedMemory`.
 */
DWORD ConnectSharedMemory(HANDLE hMemory);


/**
 * @param	pszName		The unique name of "shared memory".
 * @param	uSize		The length of "shared memory", in bytes.
 *
 * @return	A handle of "shared memory" you create 	
 */
HANDLE CreateSharedMemory(PSTR pszName, DWORD uSize);


/**
 * @param	hMemory		A handle to "shared memory".
 * @param	pBuffer		A pointer to the buffer that receives the data read from "shared memory".
 * @param	nSize		The maximum number of bytes to be read.
 * @param	pBytesRead	A pointer to the variable that receives the number of bytes read.
 *
 * @return	If the functions succeeds, the return value is TRUE, or FALSE otherwise.
 */
BOOL ReadSharedMemory(HANDLE hMemory, PVOID pBuffer, DWORD nSize, PDWORD pBytesRead);


/**
 * @param	hMemory		A handle to "shared memory".
 * @param	pBuffer		A pointer to the buffer containing the data to be written to "shared memory".
 * @param	nSize		The number of bytes to be written.	
 * @param	pBytesRead	A pointer to the variable that receives the number of bytes written.
 *
 * @return	If the functions succeeds, the return value is TRUE, or FALSE otherwise.
 */
BOOL WriteSharedMemory(HANDLE hMemory, PVOID pBuffer, DWORD nSize, PDWORD pBytesWritten);


/**
 * @param	hMemory		A handle to "shared memory".
 */
VOID FreeSharedMemory(HANDLE hMemory);

#endif // IOCTL_H
