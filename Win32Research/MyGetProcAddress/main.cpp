// 核心是实现自己的GetProcAddress
//
// https://en.wikipedia.org/wiki/Win32_Thread_Information_Block

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include "Header.h"

VOID EnumLoadedModules()
{
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY head, p;

	_asm
	{
		mov eax, fs:[0x30]; /* Linear address of PEB */
		mov eax, [eax + 0xc];
		mov Ldr, eax;
	}

	head = Ldr->InLoadOrderModuleList.Flink;
	p = head;
	do
	{
		PLDR_MODULE ldr = (PLDR_MODULE)p;
		printf("FullDllName: %ws\n", ldr->FullDllName.Buffer);
		printf("BaseDllName: %ws\n\n", ldr->BaseDllName.Buffer);
		p = p->Flink;
	} while (p != head);
}

HMODULE MyGetModuleHandle(PWSTR ModuleName)
{
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY head, p;

	_asm
	{
		mov eax, fs:[0x30]; /* Linear address of PEB */
		mov eax, [eax + 0xc];
		mov Ldr, eax;
	}

	head = Ldr->InLoadOrderModuleList.Flink;
	p = head;
	do
	{
		PLDR_MODULE ldr = (PLDR_MODULE)p;
		if (!lstrcmpi(ModuleName, ldr->BaseDllName.Buffer)) { return (HMODULE)ldr->BaseAddress; }
		if (!lstrcmpi(ModuleName, ldr->FullDllName.Buffer)) { return (HMODULE)ldr->BaseAddress; }
		p = p->Flink;
	} while (p != head);

	return NULL;
}

BOOL MyGetModuleFileName(HMODULE hModule, PSTR FileName)
{
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY head, p;

	_asm
	{
		mov eax, fs:[0x30]; /* Linear address of PEB */
		mov eax, [eax + 0xc];
		mov Ldr, eax;
	}

	head = Ldr->InLoadOrderModuleList.Flink;
	p = head;
	do
	{
		PLDR_MODULE ldr = (PLDR_MODULE)p;
		if (hModule == ldr->BaseAddress)
		{
			sprintf(FileName, "%ws", ldr->BaseDllName.Buffer);
			return TRUE;
		}
		p = p->Flink;
	} while (p != head);

	return FALSE;
}

// `ImportModuleName'是`hModule'的一个导入模块,`hModule'从中导入了名为`ImportProcName'的函数.
// 该函数从`hModule'的IAT中找到目标函数`ImportProcName'的入口地址.
FARPROC GetProcAddressFromIAT(HMODULE hModule, PSTR ImportModuleName, PSTR ImportProcName)
{
	PBYTE base = (PBYTE)hModule;
	if (base == NULL) { return NULL; }

	PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(base + dos_hdr->e_lfanew);
	DWORD import_tb_rva = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD import_tb_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD nr_import_ent = import_tb_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	PIMAGE_IMPORT_DESCRIPTOR import_ent = (PIMAGE_IMPORT_DESCRIPTOR)(base + import_tb_rva);
	
	for (int i = 0; i < nr_import_ent; i++, import_ent++)
	{
		PSTR name = (PSTR)(base + import_ent->Name);
		
		if (!_stricmp(name, ImportModuleName))
		{
			PDWORD import_addr_ent = (PDWORD)(base + import_ent->FirstThunk); // FirstThunk = Import Address Table RVA
			PDWORD func_name_rva = (PDWORD)(base + import_ent->Characteristics); // Characteristics = Import Name Table RVA

			for (; *func_name_rva && *import_addr_ent; func_name_rva++, import_addr_ent++)
			{
				if (*func_name_rva & 0x80000000) continue; // *func_name_rva is actually an ordinal

				PSTR func_name = (PSTR)(base + *func_name_rva + 2); // skip first two bytes
				if (!strcmp(func_name, ImportProcName))
				{
					return (FARPROC)(*import_addr_ent);
				}
			}
		}
	}

	return NULL;
}

FARPROC MyGetProcAddress(HMODULE hModule, PSTR ProcName)
{
	PBYTE base = (PBYTE)hModule;
	if (base == NULL) { return NULL; }

	PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(base + dos_hdr->e_lfanew);
	DWORD export_tb_rva = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD export_tb_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_EXPORT_DIRECTORY export_tb = (PIMAGE_EXPORT_DIRECTORY)(base + export_tb_rva);
	DWORD nr_funcs = export_tb->NumberOfFunctions;
	DWORD nr_names = export_tb->NumberOfNames;
	DWORD funcs_rva = export_tb->AddressOfFunctions;
	DWORD names_rva = export_tb->AddressOfNames;
	DWORD ordinals_rva = export_tb->AddressOfNameOrdinals;
	DWORD ordinal_base = export_tb->Base;
	PDWORD funcs = (PDWORD)(base + funcs_rva);
	PDWORD names = (PDWORD)(base + names_rva);
	PWORD ordinals = (PWORD)(base + ordinals_rva);

	CHAR file_name[MAX_PATH];
	memset(file_name, 0, sizeof(file_name));
	MyGetModuleFileName(hModule, file_name);

	// 序号表ordinals[nr_names]存放的是通过名字导出的函数的入口RVA在函数地址表`funcs'中的索引.
	// 如果一个函数仅通过序号导出,则需要将序号减去`ordinal_base'才能得到函数的入口RVA在`funcs'
	// 中的索引.

	if (((DWORD)ProcName & 0xffff0000) == 0) // `ProcName' is actually an ordinal
	{
		return (FARPROC)(base + funcs[(WORD)ProcName - ordinal_base]);
	}

	for (int i = 0; i < nr_names; i++)
	{
		PSTR name = (PSTR)(base + names[i]);
		DWORD func_rva = funcs[ordinals[i]];

		if (!strcmp(name, ProcName))
		{
			/**
			 * http://mcdermottcybersecurity.com/articles/windows-x64-shellcode
			 *
			 * The interpretation of `func_rva' depends on whether the function is forwarded.
			 * Export Forwarding is a mechanism by which a DLL can declare that an exported function is
			 * actually implemented in a different DLL. If the function is not forwarded, the value is an
			 * RVA pointing to the actual function code. If the function is forwarded, the RVA points to an
			 * ASCII string giving the target DLL and function name. You can tell in advance if a function
			 * is forwarded based on the range of the RVA – the function is forwarded if the RVA falls within
			 * the export directory (as given by the VirtualAdress and Size in the IMAGE_DATA_DIRECTORY entry).
			 */
			if (func_rva - export_tb_rva < export_tb_size) // this function is forwarded.
			{
				CHAR dll_name[MAX_PATH], func_name[MAX_PATH];
				memset(dll_name, 0, sizeof(dll_name));
				memset(func_name, 0, sizeof(func_name));
				
				PSTR sz = (PSTR)(base + func_rva);
				PSTR p = strchr(sz, '.');
				int dll_name_len = p - sz;
				strncpy(dll_name, sz, dll_name_len);
				strcat(dll_name, ".DLL");
				strcpy(func_name, p + 1);

				// 这个函数就是本模块导出的,只不过它是一个别名,所以不会造成无限递归.
				// 例如: rpcrt4.dll中 l_RpcBindinglnqDynamicEndpoint -> RPCRT4.l_RpcBindinglnqDynamicEndpointW
				if (!_stricmp(file_name, dll_name)) { return MyGetProcAddress(hModule, func_name); }

				// 这个函数是从别的DLL导入的,然后本模块再将其导出,可以查导入表.
				FARPROC entry = GetProcAddressFromIAT(hModule, dll_name, func_name);
				if (entry) { return entry; }

				// 查导入表无果,尝试加载该DLL模块.
				HMODULE hTemp = LoadLibraryA(dll_name);
				if (hTemp == hModule)
				{
					// 此时如果递归调用,会爆栈.根据Kernel32.DLL的测试结果,可以另行加载KernelBase.DLL,然后再递归.
					hTemp = MyGetModuleHandle(TEXT("KernelBase.DLL"));
				}
				return MyGetProcAddress(hTemp, func_name);
			}
			else // this function is NOT forwarded.
			{
				return (FARPROC)(base + func_rva);
			}
		}
	}

	return NULL;
}

// 对于DLL模块中的每一个以名字导出的函数,测试`MyGetProcAddress()`的返回值与`GetProcAddress()`是否相等.
void test_MyGetProcAddress(PWSTR ModuleName)
{
	HMODULE hModule = MyGetModuleHandle(ModuleName);
	if (hModule == NULL) { goto LABEL_FAILED; }

	PBYTE base = (PBYTE)hModule;
	PIMAGE_DOS_HEADER dos_hdr = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(base + dos_hdr->e_lfanew);
	DWORD export_tb_rva = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD export_tb_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	PIMAGE_EXPORT_DIRECTORY export_tb = (PIMAGE_EXPORT_DIRECTORY)(base + export_tb_rva);
	DWORD nr_names = export_tb->NumberOfNames;
	DWORD names_rva = export_tb->AddressOfNames;
	PDWORD names = (PDWORD)(base + names_rva);

	bool flag = true;
	for (int i = 0; i < nr_names; i++)
	{
		PSTR name = (PSTR)(base + names[i]);
		FARPROC p1 = MyGetProcAddress(hModule, name);
		FARPROC p2 = GetProcAddress(hModule, name);
		if (p1 != p2)
		{
			flag = false;
			printf("error caused by %s\n", name);
		}
	}

	if (flag)
	{
		printf("test_MyGetProcAddress(%ws) passed.\n", ModuleName);
	}
	else
	{
LABEL_FAILED:
		printf("test_MyGetProcAddress(%ws) failed.\n", ModuleName);
	}
}

int main()
{
	WCHAR ModuleName[32];
	MessageBox(0, NULL, NULL, 0); // 导入更多的DLL
	
	EnumLoadedModules();
	printf("Which module do you wanna test? ");
	scanf("%ws", ModuleName);
	test_MyGetProcAddress(ModuleName);
}