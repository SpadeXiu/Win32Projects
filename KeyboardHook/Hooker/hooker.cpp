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

// ���� ���ݸ� EnumWindows �Ļص����� EnumWindowProc �Ĳ����ṹ��
typedef struct {
	LPWSTR lpszPartWindowName; // �������
	LPWSTR lpszFullWindowName; // �������
	UINT uSize; // �������
} ENUMWINPROCPRARM, *PENUMWINPROCPRARM;

///////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL CALLBACK EnumWindowProc(HWND hWnd, LPARAM lParam) {
	PENUMWINPROCPRARM pParam = (PENUMWINPROCPRARM)lParam;
	WCHAR szFullWindowName[MAX_PATH];

	// ��ȡ����ȫ�� szFullWindowName
	GetWindowText(hWnd, szFullWindowName, pParam->uSize);
	if (wcsstr(szFullWindowName, pParam->lpszPartWindowName) == NULL) {
		// ����ȫ�� szFullWindowName ��δ�����ؼ��� lpszPartWindowName, ���Լ���ö��
		return TRUE; // ���ص��������� TRUE, EnumWindows �����ö��
	}
	else {
		// ƥ��ɹ�, �������ȫ��
		lstrcpyW(pParam->lpszFullWindowName, szFullWindowName);
		return FALSE; // �ص��������� FALSE, EnumWindows ����ö�ٲ�����
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void GetFullWindowName(
	_In_ LPWSTR lpszPartWindowName, // �������ؼ���
	_Out_ LPWSTR lpszFullWindowName, // �����ؼ��ֵĴ���ȫ��
	_In_ UINT uSize) // �������ĳ���
{
	// �������ṹ��
	ENUMWINPROCPRARM param;
	param.lpszPartWindowName = lpszPartWindowName;
	param.lpszFullWindowName = lpszFullWindowName;
	param.uSize = uSize;

	// �������㴰��
	EnumWindows(EnumWindowProc, (LPARAM)&param); // �� param �ṹ��ĵ�ַ��Ϊ LONG_PTR �����ص�����
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void Dlg_OnInitDialog(HWND hWnd) {
	HWND hItem = GetDlgItem(hWnd, IDC_WINNAME);
	SetFocus(hItem);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

void Dlg_OnCommand(HWND hWnd, int id) {
	WCHAR szPartWindowName[MAX_PATH]; // �������ؼ���
	WCHAR szFullWindowName[MAX_PATH]; // ����ȫ��
	HMODULE hLibInst = NULL;
	pfn_InstallHook InstallHook = NULL;
	pfn_UninstallHook UninstallHook = NULL;

	switch (id) {
	case IDCANCEL:
		EndDialog(hWnd, id);
		break;

	case IDC_BUTTON_HOOK:
		// ��ȡ�û�����Ĵ������ؼ���
		GetDlgItemText(hWnd, IDC_WINNAME, szPartWindowName, MAX_PATH);
		// ���ݴ������ؼ��ֻ�ȡ����ȫ��
		GetFullWindowName(szPartWindowName, szFullWindowName, MAX_PATH);
		// Hook it!
		hLibInst = LoadLibrary(TEXT("Hook.dll"));
		if (hLibInst != NULL) {
			InstallHook = (pfn_InstallHook)GetProcAddress(hLibInst, "InstallHook");
			if (InstallHook != NULL) {
				// InstallHook �����Դ���ȫ����Ϊ�������
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