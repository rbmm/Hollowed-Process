#include "stdafx.h"

BOOLEAN IsImageOk(_In_ ULONG SizeOfImage, _In_ HANDLE hSection)
{
	BOOLEAN fOk = FALSE;

	SIZE_T ViewSize = 0;
	union {
		PVOID BaseAddress = 0;
		PIMAGE_DOS_HEADER pidh;
	};

	if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, 
		&ViewSize, ViewUnmap, 0, PAGE_READONLY))
	{
		if (ViewSize >= SizeOfImage && pidh->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG VirtualAddress = pidh->e_lfanew;

			if (VirtualAddress < ViewSize - sizeof(IMAGE_NT_HEADERS))
			{
				union {
					PVOID pv;
					PIMAGE_NT_HEADERS pinth;
					PIMAGE_LOAD_CONFIG_DIRECTORY picd;
				};

				pv = RtlOffsetToPointer(BaseAddress, VirtualAddress);
				PIMAGE_SECTION_HEADER pish = 0;
				DWORD NumberOfSections = 0;

				if (pinth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC && 
					pinth->OptionalHeader.SizeOfImage >= SizeOfImage)
				{
					if (NumberOfSections = pinth->FileHeader.NumberOfSections)
					{
						pish = IMAGE_FIRST_SECTION(pinth);
					}

					IMAGE_DATA_DIRECTORY DataDirectory = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

					if (!DataDirectory.VirtualAddress)
					{
						fOk = TRUE;
					}
					else
					{
						if (DataDirectory.VirtualAddress < ViewSize - sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
						{
							pv = RtlOffsetToPointer(BaseAddress, DataDirectory.VirtualAddress);

							fOk = picd->Size < __builtin_offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) || 
								!picd->GuardCFFunctionCount;
						}
					}

					if (fOk)
					{
						if (pish)
						{
							VirtualAddress = (pinth->OptionalHeader.SizeOfHeaders + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
							do
							{
								DWORD VirtualSize = pish->Misc.VirtualSize;

								if (!VirtualSize)
								{
									continue;
								}

								if (VirtualAddress != pish->VirtualAddress)
								{
									fOk = FALSE;
									break;
								}

								VirtualAddress += VirtualSize + PAGE_SIZE - 1;

								VirtualAddress &= ~(PAGE_SIZE - 1);

							} while (pish++, --NumberOfSections);
						}
						else
						{
							fOk = FALSE;
						}
					}
				}
			}
		}

		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	}

	return fOk;
}

NTSTATUS FindNoCfgDll(_In_ ULONG SizeOfImage, _Out_ PHANDLE SectionHandle)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, L"\\systemroot\\system32");

	NTSTATUS status = NtOpenFile(&oa.RootDirectory,
		FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

	if (0 <= status)
	{
		status = STATUS_NO_MEMORY;

		enum { buf_size = 0x10000 };

		if (PVOID buf = LocalAlloc(0, buf_size))
		{
			static const UNICODE_STRING DLL = RTL_CONSTANT_STRING(L"*.dll");

			while (0 <= (status = NtQueryDirectoryFile(oa.RootDirectory,
				0, 0, 0, &iosb, buf, buf_size, FileDirectoryInformation,
				FALSE, const_cast<PUNICODE_STRING>(&DLL), FALSE)))
			{
				union {
					PVOID pv;
					PUCHAR pc;
					PFILE_DIRECTORY_INFORMATION pfdi;
				};

				pv = buf;

				ULONG NextEntryOffset = 0;

				do
				{
					pc += NextEntryOffset;

					if (pfdi->EndOfFile.QuadPart >= SizeOfImage)
					{
						ObjectName.Buffer = pfdi->FileName;
						ObjectName.MaximumLength = ObjectName.Length = (USHORT)pfdi->FileNameLength;

						if (0 <= NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ,
							FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT))
						{
							BOOLEAN fOk = FALSE;

							HANDLE hSection;

							if (0 <= NtCreateSection(&hSection, SECTION_MAP_READ, 0, 0, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile))
							{
								fOk = IsImageOk(SizeOfImage, hSection);

								NtClose(hSection);

								if (fOk)
								{
									fOk = 0 <= NtCreateSection(SectionHandle,
										SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE,
										0, 0, PAGE_WRITECOPY, SEC_IMAGE, hFile);
								}
							}

							NtClose(hFile);

							if (0 <= status)
							{
								if (fOk)
								{
									//DbgPrint("%I64x %wZ\n", pfdi->EndOfFile.QuadPart, &ObjectName);

									goto __exit;
								}
							}
						}
					}

				} while (NextEntryOffset = pfdi->NextEntryOffset);
			}
__exit:
			LocalFree(buf);
		}
		NtClose(oa.RootDirectory);
	}

	return status;
}