#ifndef HOOK_H
#define HOOK_H
#include <Windows.h>

BOOL InstallHook(LPCWSTR lpWindowName);
BOOL UninstallHook();

#endif // HOOK_H