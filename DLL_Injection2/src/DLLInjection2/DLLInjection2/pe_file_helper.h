#ifndef PE_FILE_HELPER
#define PE_FILE_HELPER

#include <Windows.h>
#include <stdio.h>
#include <assert.h>
#include <iostream>

#include "file_mapping.h"

class PeFileHelper
{
public:
	PeFileHelper(PCWSTR pszFileName);
	~PeFileHelper();
	void SeekToNtHeaders();
	void SeekToSectionHeader();
	void SeekToImportDirectoryTable();
	void ReleaseBoundImportTable();
	void InjectDll(PCSTR pszFileName, PCSTR pszProcName);
private:
	DWORD Rva2Offset(DWORD dwRva);
private:
	FileMapping m_FileMapping;
	PVOID m_pFileBase;
	PCHAR m_pCurrentFilePointer;
	PIMAGE_DOS_HEADER m_pDosHeader;
	PIMAGE_NT_HEADERS m_pNtHeaders;
};

#endif /* PE_FILE_HELPER */
