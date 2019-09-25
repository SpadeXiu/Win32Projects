#include "pe_file_helper.h"

PeFileHelper::PeFileHelper(LPCWSTR pszFileName):m_FileMapping(pszFileName)
{
	m_pFileBase = m_FileMapping.GetFileMappingBase();
	assert(m_pFileBase != NULL);
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBase;
	m_pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)m_pFileBase + m_pDosHeader->e_lfanew);
}

PeFileHelper::~PeFileHelper()
{
	m_FileMapping.Flush();
}

void PeFileHelper::SeekToNtHeaders()
{
	m_pCurrentFilePointer = (PCHAR)m_pNtHeaders;
}

void PeFileHelper::SeekToSectionHeader()
{
	m_pCurrentFilePointer = (PCHAR)m_pNtHeaders + sizeof(IMAGE_NT_HEADERS);
}

void PeFileHelper::SeekToImportDirectoryTable()
{
	DWORD importDirectoryTableRva = m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	m_pCurrentFilePointer = (PCHAR)m_pFileBase + Rva2Offset(importDirectoryTableRva);
}

void PeFileHelper::InjectDll(PCSTR pszFileName, PCSTR pszProcName)
{
	DWORD numSections = m_pNtHeaders->FileHeader.NumberOfSections;
	SeekToSectionHeader();
	PIMAGE_SECTION_HEADER pFirstSectionHeader = (PIMAGE_SECTION_HEADER)m_pCurrentFilePointer;
	PIMAGE_SECTION_HEADER pLastSectionHeader = pFirstSectionHeader + numSections - 1;
	PCHAR pLastSectionStart = (PCHAR)m_pFileBase + pLastSectionHeader->PointerToRawData;
	PCHAR pLastSectionEnd = pLastSectionStart + pLastSectionHeader->SizeOfRawData;

	SeekToImportDirectoryTable();
	PIMAGE_IMPORT_DESCRIPTOR pFirstIDTEntry = (PIMAGE_IMPORT_DESCRIPTOR)m_pCurrentFilePointer;
	DWORD oldIDTSize = m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	DWORD newIDTSize = oldIDTSize + sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD lastSectionSizeIncrement = newIDTSize + // IDT, new entry included
		sizeof(void*) * 2 + // INT - one entry for pszProcName, one entry for NULL
		sizeof(void*) * 2 + // IAT - one entry for pszProcName, one entry for NULL
		strlen(pszFileName) + 1 +
		sizeof(WORD) + strlen(pszProcName) + 1;

	PCHAR p = pLastSectionEnd;
	PCHAR pINT, pIAT, ppszFileName, ppszProcName;
	memcpy(p, pFirstIDTEntry, oldIDTSize);
	p += oldIDTSize;
	memset(p, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR)); // for new IDT entry
	p += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	pINT = p;
	pIAT = p + sizeof(void*) * 2;
	memset(p, 0, sizeof(void*) * 8); // for INT and IAT
	p += sizeof(void*) * 8;
	ppszFileName = p;
	strcpy(p, pszFileName);
	p += strlen(pszFileName) + 1;
	memset(p, 0, sizeof(WORD));
	ppszProcName = p;
	p += sizeof(WORD);
	strcpy(p, pszProcName);

	PIMAGE_IMPORT_DESCRIPTOR pNewIDTEntry = (PIMAGE_IMPORT_DESCRIPTOR)
		(pLastSectionEnd + oldIDTSize - sizeof(IMAGE_IMPORT_DESCRIPTOR)); // oldIDTSize包含了最后一个空结构体的大小, 所以要减回去

	// 填充Import Name Table(INT)
	*(DWORD*)pINT = pLastSectionHeader->VirtualAddress + (ppszProcName - pLastSectionStart);
	// 填充Import Address Table(IAT)
	*(DWORD*)pIAT = *(DWORD*)pINT;
	// RVA to INT
	pNewIDTEntry->OriginalFirstThunk = pLastSectionHeader->VirtualAddress + (pINT - pLastSectionStart);
	// RVA to DLL name(pszFileName)
	pNewIDTEntry->Name = pLastSectionHeader->VirtualAddress + (ppszFileName - pLastSectionStart);
	// RVA to Import Address Table(IAT)
	pNewIDTEntry->FirstThunk = pLastSectionHeader->VirtualAddress + (pIAT - pLastSectionStart);

	// 修改NT Headers中记录IDT的RVA和Size, 使其对应新的IDT
	m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
		pLastSectionHeader->VirtualAddress + pLastSectionHeader->SizeOfRawData;
	m_pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = newIDTSize;

	// 将最后一个节扩大 lastSectionSizeIncrement 个字节
	DWORD fileAlignment = m_pNtHeaders->OptionalHeader.FileAlignment;
	DWORD x = pLastSectionHeader->SizeOfRawData + lastSectionSizeIncrement;
	pLastSectionHeader->SizeOfRawData = (x + fileAlignment - 1) / fileAlignment * fileAlignment;
	pLastSectionHeader->Misc.VirtualSize = pLastSectionHeader->SizeOfRawData;
	pLastSectionHeader->Characteristics |= IMAGE_SCN_MEM_WRITE;
	
	return;
}

DWORD PeFileHelper::Rva2Offset(DWORD dwRva)
{
	DWORD numSections = m_pNtHeaders->FileHeader.NumberOfSections;
	SeekToSectionHeader();
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)m_pCurrentFilePointer;

	for (DWORD i = 0; i < numSections; i++) {
		DWORD rvaStart = pSectionHeader->VirtualAddress;
		DWORD rvaEnd = rvaStart + pSectionHeader->SizeOfRawData;
		if (dwRva >= rvaStart && dwRva <= rvaEnd) {
			DWORD dwRva2 = dwRva - rvaStart;
			return pSectionHeader->PointerToRawData + dwRva2;
		}
		pSectionHeader++;
	}
	return 0;
}