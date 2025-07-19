#include "stdafx.h"

_NT_BEGIN

NTSTATUS FindNoCfgDll(_In_ ULONG Machine, _In_ ULONG Magic, _In_ ULONG SizeOfImage, _Out_ PHANDLE SectionHandle);

struct PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN IsLongPathAwareProcess : 1;
		};
	};
	ULONG Mutant;
	ULONG ImageBaseAddress;
};

void CopyImage(PVOID BaseAddress, PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth, ULONG SizeOfHeaders)
{
	memcpy(BaseAddress, BaseOfImage, SizeOfHeaders);

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
		PIMAGE_NT_HEADERS pinth;
		PIMAGE_NT_HEADERS32 pinth32;
		PIMAGE_NT_HEADERS64 pinth64;
	};

	LONG_PTR Delta = 0;

	pinth = RtlImageNtHeader(BaseAddress);

	switch (pinth->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		pv = &pinth32->OptionalHeader.ImageBase;
		Delta = RemoteBase - *(ULONG*)pv;
		*(ULONG*)pv = (ULONG)RemoteBase;
		break;

	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		pv = &pinth64->OptionalHeader.ImageBase;
		Delta = RemoteBase - *(ULONG64*)pv;
		*(ULONG64*)pv = RemoteBase;
		break;
	}

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
			if (SIZE_T VirtualSize = pish->Misc.VirtualSize)
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

				PVOID BaseAddress = (PBYTE)RemoteBase + pish->VirtualAddress;
				NTSTATUS status = ZwProtectVirtualMemory(hProcess, &BaseAddress, &VirtualSize, NewProtect, &NewProtect);
				if (0 > status)
				{
					return status;
				}
			}
		} while (pish++, --NumberOfSections);
	}

	return STATUS_SUCCESS;
}

NTSTATUS WINAPI GetWowContext( _In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context)
{
	return ZwQueryInformationThread(ThreadHandle, ThreadWow64Context, Context, sizeof(WOW64_CONTEXT), 0);
}

NTSTATUS WINAPI SetWowContext( _In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context)
{
	return ZwSetInformationThread(ThreadHandle, ThreadWow64Context, Context, sizeof(WOW64_CONTEXT));
}

BOOL InjDll(HANDLE hProcess, HANDLE hThread)
{
	BOOL fOk = FALSE;

	if (WCHAR* buf = new WCHAR[0x8000])
	{
		if (SIZE_T cb = GetFullPathNameW(L"MoveToBand.dll", 0x8000, buf, 0))
		{
			if (PVOID pv = VirtualAllocEx(hProcess, 0, cb = ++cb * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE))
			{
				if (0 <= ZwWriteVirtualMemory(hProcess, pv, buf, cb, &cb))
				{
					fOk = 0 <= ZwQueueApcThread(hThread, (PPS_APC_ROUTINE)LoadLibraryExW, pv, 0, 0);
				}
			}
		}
		delete[] buf;
	}

	return fOk;
}

#define CONTEXT_i386 0x00010000L 

BOOL Exec(PVOID BaseOfImage, PIMAGE_NT_HEADERS pinth, PCWSTR lpCmdLine)
{
	ULONG SizeOfImage = 0;
	ULONG SizeOfHeaders = 0;
	BOOL b32;
	union {
		CONTEXT ctx {};
		WOW64_CONTEXT wctx;
	};

	UINT (WINAPI * GetSystemDirectory)(PWSTR lpBuffer, UINT uSize) = 0;
	NTSTATUS (WINAPI * GetCtx)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context) = 0;
	NTSTATUS (WINAPI * SetCtx)(_In_ HANDLE ThreadHandle, _Inout_ PCONTEXT Context) = 0;

	switch (pinth->OptionalHeader.Magic)
	{
	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
		SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS32>(pinth)->OptionalHeader.SizeOfImage;
		SizeOfHeaders = reinterpret_cast<PIMAGE_NT_HEADERS32>(pinth)->OptionalHeader.SizeOfHeaders;
		GetSystemDirectory = GetSystemWow64DirectoryW;
		wctx.ContextFlags = (CONTEXT_INTEGER & ~CONTEXT_AMD64)|CONTEXT_i386;
		GetCtx = GetWowContext;
		SetCtx = SetWowContext;
		b32 = TRUE;
		break;

	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
		SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS64>(pinth)->OptionalHeader.SizeOfImage;
		SizeOfHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(pinth)->OptionalHeader.SizeOfHeaders;
		GetSystemDirectory = GetSystemWindowsDirectoryW;
		ctx.ContextFlags = CONTEXT_INTEGER;
		GetCtx = ZwGetContextThread;
		SetCtx = ZwSetContextThread;
		b32 = FALSE;
		break;

	default: return FALSE;
	}

	BOOL fOk = FALSE;
	HANDLE hSection;

	if (0 <= FindNoCfgDll(pinth->FileHeader.Machine, pinth->OptionalHeader.Magic, SizeOfImage, &hSection))
	{
		SIZE_T ViewSize = 0;
		PVOID BaseAddress = 0;

		if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), 
			&BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_NOACCESS))
		{
			ULONG op;
			PVOID pv = BaseAddress;
			SIZE_T RegionSize = SizeOfImage;

			if (0 <= ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &RegionSize, PAGE_READWRITE, &op))
			{
				RtlZeroMemory(BaseAddress, SizeOfImage);

				CopyImage(BaseAddress, BaseOfImage, pinth, SizeOfHeaders);

				WCHAR buf[MAX_PATH];

				if (ULONG cch = GetSystemDirectory(buf, _countof(buf) - _countof("\\explorer.exe")))
				{
					wcscpy(buf + cch, L"\\explorer.exe");
				}

				STARTUPINFO si = { sizeof(si) };
				PROCESS_INFORMATION pi;

				if (CreateProcessW(buf, const_cast<PWSTR>(lpCmdLine), 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
				{
					PROCESS_BASIC_INFORMATION pbi;
					PEB32* wow;

					PVOID RemoteBase = 0;
					ViewSize = SizeOfImage;

					if (0 <= NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0) &&
						0 <= NtQueryInformationProcess(pi.hProcess, ProcessWow64Information, &wow, sizeof(wow), 0) &&
						0 <= GetCtx(pi.hThread, &ctx) &&
						0 <= ZwMapViewOfSection(hSection, pi.hProcess, &RemoteBase, 0, 0, 0, &ViewSize, ViewShare, 0, PAGE_READONLY))
					{
						Relocate(BaseAddress, (LONG_PTR)RemoteBase);

						ULONG_PTR AddressOfEntryPoint = (ULONG_PTR)RemoteBase + pinth->OptionalHeader.AddressOfEntryPoint;
						
						if (b32)
						{
							wctx.Eax = (ULONG)AddressOfEntryPoint;
						}
						else
						{
							ctx.Rcx = AddressOfEntryPoint;
							ctx.R8 = 0x8888888888888888;
							ctx.R9 = 0x9999999999999999;
						}

						fOk = 0 <= ZwProtectVirtualMemory(pi.hProcess, &(pv = RemoteBase), &(RegionSize = SizeOfImage), PAGE_READWRITE, &op) &&
							0 <= ZwWriteVirtualMemory(pi.hProcess, RemoteBase, BaseAddress, SizeOfImage, 0) &&
							0 <= ProtectImage(pi.hProcess, RemoteBase, pinth) &&
							0 <= ZwWriteVirtualMemory(pi.hProcess, &reinterpret_cast<PEB*>(pbi.PebBaseAddress)->ImageBaseAddress, &RemoteBase, sizeof(RemoteBase), 0) &&
							0 <= (wow ? ZwWriteVirtualMemory(pi.hProcess, &wow->ImageBaseAddress, &RemoteBase, sizeof(ULONG), 0) : 0) &&
							0 <= SetCtx(pi.hThread, &ctx) &&
							InjDll(pi.hProcess, pi.hThread) &&
							0 <= ZwResumeThread(pi.hThread, 0);
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

	return fOk;
}

NTSTATUS ReadF(HANDLE hFile, void** pbuf, PIO_STATUS_BLOCK iosb)
{
	FILE_STANDARD_INFORMATION fsi;
	NTSTATUS status;
	if (0 <= (status = NtQueryInformationFile(hFile, iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		status = STATUS_FILE_TOO_LARGE;

		if (fsi.EndOfFile.QuadPart - 1 < MAXLONG)
		{
			status = STATUS_NO_MEMORY;

			if (PVOID buf = new UCHAR[fsi.EndOfFile.LowPart])
			{
				if (0 <= (status = NtReadFile(hFile, 0, 0, 0, iosb, buf, fsi.EndOfFile.LowPart, 0, 0)))
				{
					*pbuf = buf;
					return status;
				}
				delete [] buf;
			}
		}
	}

	return status;
}

NTSTATUS Exec(PCWSTR psz, PCWSTR lpCmdLine)
{
	UNICODE_STRING ObjectName;
	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(psz, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
		status = NtOpenFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			PVOID buf;
			status = ReadF(hFile, &buf, &iosb);
			NtClose(hFile);
			if (0 <= status)
			{
				PIMAGE_NT_HEADERS pinth;
				if (0 <= (status = RtlImageNtHeaderEx(0, buf, iosb.Information, &pinth)))
				{
					Exec(buf, pinth, lpCmdLine);
				}
				delete [] buf;
			}
		}
	}
	return status;
}

NTSTATUS Exec(PWSTR lpCmdLine = GetCommandLineW())
{
	if (PWSTR lpAppName = wcschr(lpCmdLine, '*'))
	{
		if (lpCmdLine = wcschr(++lpAppName, '*'))
		{
			*lpCmdLine = 0;
			return Exec(lpAppName, lpCmdLine + 1);
		}
	}
	return STATUS_INVALID_PARAMETER;
}

void WINAPI ep(void*)
{
	Exec();
	ExitProcess(0);
}

_NT_END