#include <assert.h>
#include "file_mapping.h"

FileMapping::FileMapping(PCWSTR pszFileName)
	:m_hFile(INVALID_HANDLE_VALUE),
	m_hFileMapping(INVALID_HANDLE_VALUE),
	m_pFileMappingBase(NULL)
{
	m_hFile = ::CreateFile(pszFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	assert(m_hFile != INVALID_HANDLE_VALUE);

	DWORD dwFileSize = ::GetFileSize(m_hFile, NULL);
	m_hFileMapping = ::CreateFileMapping(m_hFile, NULL, PAGE_READWRITE, 0, dwFileSize, pszFileName);
	assert(m_hFileMapping != INVALID_HANDLE_VALUE);

	m_pFileMappingBase = ::MapViewOfFile(m_hFileMapping, FILE_MAP_WRITE, 0, 0, 0);
	assert(m_pFileMappingBase != NULL);
}

PVOID FileMapping::GetFileMappingBase()
{
	return m_pFileMappingBase;
}

BOOL FileMapping::Flush()
{
	assert(m_pFileMappingBase != NULL);
	return ::FlushViewOfFile(m_pFileMappingBase, 0);
}

FileMapping::~FileMapping()
{
	if (m_pFileMappingBase != NULL) {
		::UnmapViewOfFile(m_pFileMappingBase);
		m_pFileMappingBase = NULL;
	}
	if (m_hFileMapping != INVALID_HANDLE_VALUE) {
		::CloseHandle(m_hFileMapping);
	}
	if (m_hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(m_hFile);
	}
}