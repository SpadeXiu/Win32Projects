#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <winnt.h>
#include <ImageHlp.h>
#include <stdio.h>
#include <assert.h>
#include <tchar.h>

#pragma comment(lib,"ImageHlp")

#define Malloc(x) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, x)
#define Free(x) HeapFree(GetProcessHeap(), 0, x)

#define ORDINAL_MASK 0x80000000

BOOL WINAPI UpdateVirtualProtect(LPVOID lpAddress, DWORD Characterictics, DWORD MemLength)
{
	DWORD NewProtect, OldProtect;
	NewProtect = 0;
	if (Characterictics & IMAGE_SCN_MEM_READ)
	{
		NewProtect |= PAGE_READONLY;
	}
	if (Characterictics & IMAGE_SCN_MEM_WRITE)
	{
		NewProtect |= PAGE_WRITECOPY; // Copy-on-Write, see "Memory Protection" in MSDN
	}
	if (Characterictics & IMAGE_SCN_MEM_EXECUTE)
	{
		NewProtect |= PAGE_EXECUTE;
	}
	return VirtualProtect(lpAddress, MemLength, NewProtect, &OldProtect);
}

LPVOID WINAPI VirtualPageAlloc(DWORD ImageBase, DWORD ImageSize)
{
	MEMORY_BASIC_INFORMATION mbi;
	ZeroMemory(&mbi, sizeof(mbi));
	while (mbi.State != MEM_FREE || mbi.RegionSize < ImageSize)
	{
		if (!VirtualQuery((LPVOID)ImageBase, &mbi, sizeof(mbi)))
		{
			return NULL;
		}
		ImageBase += ImageSize;
	}
	return VirtualAlloc((LPVOID)ImageBase, ImageSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

/* 查找模块通过序号导出的函数 */
FARPROC WINAPI GetProcAddressByOrdinal(HMODULE hModule, WORD Ordinal)
{
	ULONG ulSize;
	PIMAGE_EXPORT_DIRECTORY pExportDesc = NULL;
	FARPROC ProcAddress = NULL;

	pExportDesc = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(
		(PVOID)hModule, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ulSize);

	if (pExportDesc == NULL)
		return 0; // This module has no export section or is no longer loaded.

	// Export address table (EAT) contains the RVA of all the exported functions,
	// not only exported by name but also by ordinal.
	PDWORD pExportAddressTable = (PDWORD)((PCHAR)hModule + pExportDesc->AddressOfFunctions);
	if (pExportAddressTable != NULL)
	{
		ProcAddress = (FARPROC)((PCHAR)hModule + pExportAddressTable[Ordinal]);
	}
	return ProcAddress;
}

/* 重定位模块中的地址信息 */
BOOL WINAPI RunRelocateRoutine(DWORD ActualBase, PIMAGE_NT_HEADERS pNtHeaders)
{
	// Get information of the relocation table.
	DWORD RelocTableRva =
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	DWORD RelocTableSize =
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	// Relocation begins.
	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)
		((PCHAR)ActualBase + RelocTableRva);
	for (int cb = 0;cb < RelocTableSize;)
	{
		// The number of the relocation items.
		int RelocItemCnt = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		// Type[15:0] = Attribute[15:12] + RvaLow[11:0]
		PWORD pType = (PWORD)((PCHAR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0;i < RelocItemCnt && *pType;i++, pType++)
		{
			// RVA of each relocation item.
			DWORD ItemRva = pBaseReloc->VirtualAddress | (*pType & 0x0FFF);

			// Actual address of each relocation item.
			PDWORD pItemAddr = (PDWORD)((PCHAR)ActualBase + ItemRva);

			// Recalculate the actual address if needs relocation.
			DWORD Offset = *pItemAddr - pNtHeaders->OptionalHeader.ImageBase;
			*pItemAddr = ActualBase + Offset;
		}
		cb += pBaseReloc->SizeOfBlock;
		pBaseReloc = (PIMAGE_BASE_RELOCATION)
			((PCHAR)pBaseReloc + pBaseReloc->SizeOfBlock); // Next block
	}
	return TRUE;
}

/* 修改各Secion所属页的属性 */
BOOL WINAPI UpdateSectionPageProtect(
	DWORD ActualBase,
	PIMAGE_NT_HEADERS pNtHeaders,
	PIMAGE_SECTION_HEADER pSectionHeader)
{
	DWORD SectionAlign = pNtHeaders->OptionalHeader.SectionAlignment;
	WORD SectionCnt = pNtHeaders->FileHeader.NumberOfSections;
	BOOL bSuccess = FALSE;

	for (int i = 0;i < SectionCnt;i++, pSectionHeader++)
	{
		int PageCnt = (pSectionHeader->Misc.VirtualSize + SectionAlign - 1) / SectionAlign;
		bSuccess &= UpdateVirtualProtect(
			(PCHAR)ActualBase + pSectionHeader->VirtualAddress,
			pSectionHeader->Characteristics,
			PageCnt * SectionAlign);
	}
	return bSuccess;
}

/* 遍历模块的导入表，加载其他模块 */
BOOL WINAPI LdrpWalkImportDescriptor(
	DWORD ActualBase, 
	PIMAGE_NT_HEADERS pNtHeaders,
	PIMAGE_SECTION_HEADER pSectionHeader)
{
	// Get information of import table.
	DWORD ImportTableRva =
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD ImportTableSize =
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
		(PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)ActualBase + ImportTableRva);
	int DescCnt = ImportTableSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);

	for (int i = 0;i < DescCnt;i++, pImportDesc++)
	{
		PCHAR pszModName = (PCHAR)ActualBase + pImportDesc->Name;
		if (*pszModName == 0) // End of import table.
		{
			break;
		}

		printf("\n===== %s =====\n", pszModName);
		HMODULE hModule = LoadLibraryA(pszModName);
		if (hModule != NULL)
		{
			// Where is the RVA of the import function name?
			PDWORD pFuncNameRva = (PDWORD)((PCHAR)ActualBase + pImportDesc->Characteristics);

			// Process each item in the import address table (IAT).
			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
				((PCHAR)ActualBase + pImportDesc->FirstThunk);
			for (;*pFuncNameRva;pFuncNameRva++, pThunk++)
			{
				DWORD ProcAddress;
				if (*pFuncNameRva & ORDINAL_MASK) // This function is exported by ordinal.
				{
					WORD Ordinal = *pFuncNameRva & ~ORDINAL_MASK;
					ProcAddress = (DWORD)GetProcAddressByOrdinal(hModule, Ordinal);
					printf("Function Ordinal: 0x%.4X\n", Ordinal);
				}
				else // This function is exported by name.
				{
					PCHAR pszFuncName = (PCHAR)ActualBase + *pFuncNameRva + 2; // skip the first two bytes.
					ProcAddress = (DWORD)GetProcAddress(hModule, pszFuncName);
					printf("Function Name: %s\n", pszFuncName);
				}
				if (ProcAddress == NULL)
					return FALSE;

				*(PDWORD)&pThunk->u1.Function = ProcAddress; // Fill the IAT item.
			}
		}
		else
		{
			return FALSE;
		}
	}
	return TRUE;
}

/* 映射模块和所需信息到内存 */
DWORD WINAPI LdrpMapModule(
	PCHAR pchBuffer,
	PIMAGE_NT_HEADERS pNtHeaders,
	PIMAGE_SECTION_HEADER pSectionHeader)
{
	DWORD ImageBase = pNtHeaders->OptionalHeader.ImageBase;
	DWORD ImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
	DWORD SectionAlign = pNtHeaders->OptionalHeader.SectionAlignment;
	WORD SectionCnt = pNtHeaders->FileHeader.NumberOfSections;
	PCHAR pDst = NULL, pSrc = NULL;

	// Allocate virtual page(s) for all the sections.
	PCHAR ActualBase = (PCHAR)VirtualPageAlloc(ImageBase, ImageSize);
	if (!ActualBase)
	{
		printf("VirtualPageAlloc Error: %d\n", GetLastError());
		return 0;
	}
	printf("Virtual page allocated: base = 0x%.8X, size = %.8X\n",
		(DWORD)ActualBase, ImageSize);

	// Map each section to the virtual page(s).
	for (int i = 0;i < SectionCnt;i++, pSectionHeader++)
	{
		printf("\nSection name: %s\n", pSectionHeader->Name);

		// How many virtual pages the section takes?
		int PageCnt = (pSectionHeader->Misc.VirtualSize + SectionAlign - 1) / SectionAlign;
		pDst = ActualBase + pSectionHeader->VirtualAddress;
		if (pSectionHeader->SizeOfRawData > 0)
		{
			pSrc = pchBuffer + pSectionHeader->PointerToRawData;
			CopyMemory(pDst, pSrc, pSectionHeader->SizeOfRawData);
		}
	}
	// Return the actual base to the caller.
	// if actual base is not equal to image base, then relocation is needed.
	return (DWORD)ActualBase;
}

int _tmain(int argc, wchar_t **argv)
{
	HANDLE hFile;
	DWORD dwFileSize;
	PCHAR pchBuffer;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;

	if (argc != 2)
	{
		printf("usage: %ws <file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	hFile = CreateFile(argv[1], GENERIC_READ, 0, NULL, 
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Error CreateFile: %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	pchBuffer = (PCHAR)Malloc(dwFileSize);
	if (pchBuffer == NULL)
	{
		printf("Error HeapAlloc: %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	DWORD cb;
	if (!ReadFile(hFile, pchBuffer, dwFileSize, &cb, NULL))
	{
		printf("Error ReadFile: %d\n", GetLastError());
		CloseHandle(hFile);
		Free(pchBuffer);
		return EXIT_FAILURE;
	}

	// 定位DOS头、NT头和Section头
	pDosHeader = (PIMAGE_DOS_HEADER)pchBuffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)(pchBuffer + pDosHeader->e_lfanew);
	pSectionHeader = (PIMAGE_SECTION_HEADER)(pchBuffer +
		pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	DWORD ActualBase = LdrpMapModule(pchBuffer, pNtHeaders, pSectionHeader);

	if (!RunRelocateRoutine(ActualBase, pNtHeaders))
	{
		printf("Relocation not needed.\n");
	}

	if (!LdrpWalkImportDescriptor(ActualBase, pNtHeaders, pSectionHeader))
	{
		printf("LdrpWalkImportDescriptor Error\n");
		return EXIT_FAILURE;
	}

	// "UpdateSectionPageProtect" always returns FALSE
	/*if (UpdateSectionPageProtect(ActualBase, pNtHeaders, pSectionHeader))
	{
		DWORD EntryPoint = (DWORD)((PCHAR)ActualBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
		_asm {
			jmp EntryPoint
		}
	}*/

	UpdateSectionPageProtect(ActualBase, pNtHeaders, pSectionHeader);
	DWORD EntryPoint = (DWORD)((PCHAR)ActualBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	_asm 
	{
		jmp EntryPoint
	}

	VirtualFree((LPVOID)ActualBase, 0, MEM_RELEASE);
	CloseHandle(hFile);
	Free(pchBuffer);
}