#ifndef COMMON_H
#define COMMON_H

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

BOOL WINAPI GetProcessPathById(
	_In_ DWORD dwProcessId,
	_Out_ LPWSTR lpszProcessName
	);

BOOL WINAPI GetProcessPathByName(
	_In_ LPWSTR lpszProcessName,
	_Out_ LPWSTR lpszProcessPath
	);

HMODULE WINAPI GetMainModuleHandleOfProcess(DWORD dwProcessId);

//////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI GetProcessPathById(
	_In_ DWORD dwProcessId,
	_Out_ LPWSTR lpszProcessPath
	)
{
	BOOL bSuccess = FALSE;
	HANDLE hSnapshot = NULL;
	MODULEENTRY32 me = { sizeof(me) };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) { return FALSE; }

	BOOL bMoreMods = Module32First(hSnapshot, &me);
	for (; bMoreMods; bMoreMods = Module32Next(hSnapshot, &me))
	{
		if (dwProcessId == me.th32ProcessID)
		{
			lstrcpy(lpszProcessPath, me.szExePath);
			bSuccess = TRUE;
			break;
		}
	}
	CloseHandle(hSnapshot);
	return bSuccess;
}


BOOL WINAPI GetProcessPathByName(
	_In_ LPWSTR lpszProcessName,
	_Out_ LPWSTR lpszProcessPath)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, TEXT("CreateToolhelp32Snapshot Error"), TEXT("ERROR"), MB_ICONERROR);
		return FALSE;
	}

	// Enumerate processes in the system, find the target process
	PROCESSENTRY32 pe = { sizeof(pe) };
	BOOL bFound = FALSE;
	BOOL bMore = Process32First(hSnapshot, &pe);
	for (; bMore; bMore = Process32Next(hSnapshot, &pe))
	{
		bFound = (lstrcmpi(pe.szExeFile, lpszProcessName) == 0);
		if (bFound) break;
	}
	if (!bFound)
	{
		MessageBox(0, TEXT("Failure to find target process"), TEXT("ERROR"), MB_ICONERROR);
		return FALSE;
	}

	// Get absolute path of the target process
	if (!GetProcessPathById(pe.th32ProcessID, lpszProcessPath))
	{
		MessageBox(0, TEXT("GetProcessPathById Error"), TEXT("ERROR"), MB_ICONERROR);
	}

	//// Get the handle of the target process
	//HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
	//	FALSE, pe.th32ProcessID);
	//if (hProcess == NULL)
	//{
	//	MessageBox(0, TEXT("Failure to open target process"), TEXT("ERROR"), MB_ICONERROR);
	//	return FALSE;
	//}

	//// Get main module of the target process
	//HMODULE hModule = GetMainModuleHandleOfProcess(pe.th32ProcessID);
	//if (hModule == NULL)
	//{
	//	MessageBox(0, TEXT("Failure to acquire main module of target process"), TEXT("ERROR"), MB_ICONERROR);
	//	return FALSE;
	//}

	//// Get absolute path of the target process
	//GetModuleFileNameEx(hProcess, hModule, lpszProcessPath, MAX_PATH);

	CloseHandle(hSnapshot);
	return TRUE;
}

// 进程的主模块通常是进程对应的exe程序文件映像.
// GetMainModuleHandleOfProcess 返回进程主模块的句柄
HMODULE WINAPI GetMainModuleHandleOfProcess(DWORD dwProcessId)
{
	HANDLE hSnapshot = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	WCHAR szProcessPath[MAX_PATH];

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) { return NULL; }

	if (!GetProcessPathById(dwProcessId, szProcessPath)) { return NULL; }

	BOOL bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!lstrcmpi(szProcessPath, me.szExePath))
		{
			CloseHandle(hSnapshot);
			return me.hModule;
		}
	}
	return NULL;
}

#endif // COMMON_H
