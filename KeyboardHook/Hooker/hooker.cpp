#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "resource.h"

typedef BOOL(*pfn_InstallHook)(LPCWSTR);
typedef BOOL(*pfn_UninstallHook)();

#define chMB(msg) MessageBoxA(GetActiveWindow(),msg,"MSG",MB_OK)
#define chERROR(msg) MessageBoxA(GetActiveWindow(),msg,"ERROR",MB_ICONERROR)

///////////////////////////////////////////////////////////////////////////////////////////////////////////

// unused
BOOL GetProcessName(
	_In_ DWORD dwProcessId,
	_Out_ LPWSTR lpszProcessname)
{
	BOOL bOk = FALSE;
	HANDLE hSnapshot = NULL;
	MODULEENTRY32 me = { sizeof(me) };

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
	if (hSnapshot == INVALID_HANDLE_VALUE) { return bOk; }

	BOOL bMoreMods = Module32First(hSnapshot, &me);
	for (;bMoreMods;bMoreMods = Module32Next(hSnapshot, &me)) {
		if (dwProcessId == me.th32ProcessID) {
			lstrcpy(lpszProcessname, me.szModule);
			bOk = TRUE;
			break;
		}
	}

	return bOk;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

// 定义 传递给 EnumWindows 的回调函数 EnumWindowProc 的参数结构体
typedef struct {
	LPWSTR lpszPartWindowName; // 输入参数
	LPWSTR lpszFullWindowName; // 输出参数
	UINT uSize; // 输入参数
} ENUMWINPROCPRARM, *PENUMWINPROCPRARM;

///////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL CALLBACK EnumWindowProc(HWND hWnd, LPARAM lParam) {
	PENUMWINPROCPRARM pParam = (PENUMWINPROCPRARM)lParam;
	WCHAR szFullWindowName[MAX_PATH];

	// 获取窗口全名 szFullWindowName
	GetWindowText(hWnd, szFullWindowName, pParam->uSize);
	if (wcsstr(szFullWindowName, pParam->lpszPartWindowName) == NULL) {
		// 窗口全名 szFullWindowName 中未包含关键字 lpszPartWindowName, 所以继续枚举
		return TRUE; // 若回调函数返回 TRUE, EnumWindows 会继续枚举
	}
	else {
		// 匹配成功, 输出窗口全名
		lstrcpyW(pParam->lpszFullWindowName, szFullWindowName);
		return FALSE; // 回调函数返回 FALSE, EnumWindows 结束枚举并返回
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void GetFullWindowName(
	_In_ LPWSTR lpszPartWindowName, // 窗口名关键字
	_Out_ LPWSTR lpszFullWindowName, // 包含关键字的窗口全名
	_In_ UINT uSize) // 输出缓存的长度
{
	// 填充参数结构体
	ENUMWINPROCPRARM param;
	param.lpszPartWindowName = lpszPartWindowName;
	param.lpszFullWindowName = lpszFullWindowName;
	param.uSize = uSize;

	// 遍历顶层窗口
	EnumWindows(EnumWindowProc, (LPARAM)&param); // 把 param 结构体的地址作为 LONG_PTR 传给回调函数
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void Dlg_OnInitDialog(HWND hWnd) {
	HWND hItem = GetDlgItem(hWnd, IDC_WINNAME);
	SetFocus(hItem);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void Dlg_OnCommand(HWND hWnd, int id) {
	WCHAR szPartWindowName[MAX_PATH]; // 窗口名关键字
	WCHAR szFullWindowName[MAX_PATH]; // 窗口全名
	HMODULE hLibInst = NULL;
	pfn_InstallHook InstallHook = NULL;
	pfn_UninstallHook UninstallHook = NULL;

	switch (id) {
	case IDCANCEL:
		EndDialog(hWnd, id);
		break;

	case IDC_BUTTON_HOOK:
		// 获取用户输入的窗口名关键字
		GetDlgItemText(hWnd, IDC_WINNAME, szPartWindowName, MAX_PATH);
		// 根据窗口名关键字获取窗口全名
		GetFullWindowName(szPartWindowName, szFullWindowName, MAX_PATH);
		// Hook it!
		hLibInst = LoadLibrary(TEXT("Hook.dll"));
		if (hLibInst != NULL) {
			InstallHook = (pfn_InstallHook)GetProcAddress(hLibInst, "InstallHook");
			if (InstallHook != NULL) {
				// InstallHook 函数以窗口全名作为输入参数
				if (!InstallHook(szFullWindowName)) {
					chERROR("Hook Failed!");
				}
			}
		}
		break;

	case IDC_BUTTON_UNHOOK:
		hLibInst = GetModuleHandle(TEXT("Hook.dll"));
		if (hLibInst != NULL) {
			UninstallHook = (pfn_UninstallHook)GetProcAddress(hLibInst, "UninstallHook");
			if (UninstallHook != NULL) {
				if (UninstallHook()) {
					chMB("Unhooked!");
				}
			}
			FreeLibrary(hLibInst);
		}
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK Dlg_Proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_COMMAND:
		Dlg_OnCommand(hWnd, LOWORD(wParam));
		break;
	case WM_INITDIALOG:
		Dlg_OnInitDialog(hWnd);
		break;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

int WINAPI WinMain(HINSTANCE g_hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow) {

	DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_DLGHOOK), NULL, Dlg_Proc);
	return 0;
}

/////////////////////////////////////////////////// End //////////////////////////////////////////////////