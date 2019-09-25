#include <Windows.h>

extern "C" __declspec(dllexport) void dummy() {}

BOOL WINAPI DllMain(HINSTANCE hInstanceDll, DWORD fdwReason, LPVOID lpReserved) {

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH: // DLL loaded
		MessageBox(0, TEXT("test"), TEXT("test"), MB_OK);
		break;
	}
	return TRUE;
}