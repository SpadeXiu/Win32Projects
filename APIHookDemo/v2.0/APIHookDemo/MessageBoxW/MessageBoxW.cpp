#include <Windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int) {
	MessageBoxW(NULL, TEXT("1st Message Box"), TEXT("1st Message Box"), MB_OK);
	MessageBoxW(NULL, TEXT("2nd Message Box"), TEXT("2nd Message Box"), MB_OK);
}