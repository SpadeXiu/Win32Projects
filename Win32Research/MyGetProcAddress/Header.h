// https://docs.microsoft.com/en-us/

#ifndef HEADER_H
#define HEADER_H
#include <Windows.h>

#if 0
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;
#endif

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
	ULONG	Length; // +0x00
	BOOLEAN	Initialized; // +0x04
	PVOID	SsHandle; // +0x08
	LIST_ENTRY InLoadOrderModuleList; // +0x0c
	LIST_ENTRY InMemoryOrderModuleList; // +0x14
	LIST_ENTRY InInitializationOrderModuleList;// +0x1c
} PEB_LDR_DATA,*PPEB_LDR_DATA;

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList; // 按加载顺序构成的模块链表 +0x00
	LIST_ENTRY              InMemoryOrderModuleList; // 按内存顺序构成的模块链表 +0x08
	LIST_ENTRY              InInitializationOrderModuleList; // 按初始化顺序构成的模块链表 +0x10
	PVOID                   BaseAddress; // 该模块的基地址 +0x18
	PVOID                   EntryPoint; // 该模块的入口 +0x1c
	ULONG                   SizeOfImage; // 该模块的影像大小 +0x20
	UNICODE_STRING          FullDllName; // 包含路径的模块名 +0x24
	UNICODE_STRING          BaseDllName; // 不包含路径的模块名 +0x2C
	ULONG                   Flags;
	SHORT                   LoadCount; // 该模块的引用计数
	SHORT                   TlsIndex;
	HANDLE                  SectionHandle;
	ULONG                   CheckSum;
	ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

#if 0
// Process Environment Block 
typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr; // +0x0c 
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, *PPEB;
#endif

#endif /* HEADER_H */
