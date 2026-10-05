#include "stdafx.h"

#include "util.h"

HRESULT GetLastHresult(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();

	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

NTSTATUS ReadFromFile(_In_ HANDLE hFile, _Out_ PVOID* ppb, _Out_ ULONG* pcb)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;

	if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		if (PVOID pb = LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
		{
			if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
			{
				LocalFree(pb);
			}
			else
			{
				*ppb = pb;
				*pcb = (ULONG)iosb.Information;
			}
		}
		else
		{
			status = STATUS_NO_MEMORY;
		}
	}

	return status;
}

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PVOID* ppb, _Out_ ULONG* pcb)
{
	UNICODE_STRING ObjectName;

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb,
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			status = ReadFromFile(hFile, ppb, pcb);
			NtClose(hFile);
		}
	}

	return status;
}
