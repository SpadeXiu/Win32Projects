#ifndef MONITOR_H
#define MONITOR_H

#include <Windows.h>
#include <TlHelp32.h>

class Monitor {
 public:
  Monitor(DWORD dwProcessId, PCWSTR pszLibFile);
  ~Monitor() = default;
  BOOL InjectLib();
  BOOL EjectLib();
  BOOL Monitor::EnablePrivilege(LPWSTR privilageName);
 public:
  DWORD m_dwProcessId;
  WCHAR m_szLibFile[MAX_PATH];
};


#endif // MONITOR
