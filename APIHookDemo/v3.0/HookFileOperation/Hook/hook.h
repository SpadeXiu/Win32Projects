#ifndef HOOK_H
#define HOOK_H

#include <Windows.h>
#include <ImageHlp.h>
#include <TlHelp32.h>

#pragma comment(lib,"ImageHlp")

#define BUF_SIZE 512
#define HOOK_LOG_FILE TEXT("hook_log.txt")

BOOL WINAPI ReplaceIATEntryInOneMod(
  PCSTR pszCalleeModName,
  PROC pfnOrig,
  PROC pfnNew,
  HMODULE hModCaller
);

BOOL WINAPI ReplaceIATEntryInAllMods(
  PCSTR pszCalleeModName,
  PROC pfnOrig,
  PROC pfnNew,
  PCSTR pszOrigProc
);

BOOL WINAPI HookApi(
  PCSTR pszOrigProc,
  PCSTR pszOrigLib,
  PCSTR pszNewProc,
  PCSTR pszNewLib,
  HMODULE hModCaller
);

#endif // HOOK_H
