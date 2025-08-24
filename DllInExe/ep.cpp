#include "stdafx.h"

_NT_BEGIN

HRESULT CALLBACK DllInstall(_In_ BOOL bInstall, _In_opt_ PWSTR pszExe)
{
	if (bInstall)
	{
		if (PWSTR pszCmdLine = wcschr(pszExe, '*'))
		{
			*pszCmdLine = 0;

			if (PWSTR buf = new WCHAR[MINSHORT])
			{
				SIZE_T s = (1 + GetModuleFileNameW((HMODULE)&__ImageBase, buf, MINSHORT)) * sizeof(WCHAR);

				if (!GetLastError())
				{
					PROCESS_INFORMATION pi;
					STARTUPINFOW si = { sizeof(si) };

					if (CreateProcessW(pszExe, pszCmdLine + 1, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
					{
						if (PVOID pv = VirtualAllocEx(pi.hProcess, 0, s, MEM_COMMIT, PAGE_READWRITE))
						{
							if (0 <= ZwWriteVirtualMemory(pi.hProcess, pv, buf, s, &s) &&
								0 <= ZwQueueApcThread(pi.hThread, (PPS_APC_ROUTINE)LoadLibraryExW, pv, 0, 0))
							{
								ResumeThread(pi.hThread);
								goto __0;
							}
						}

						TerminateProcess(pi.hProcess, 0);
					__0:
						NtClose(pi.hThread);
						NtClose(pi.hProcess);
					}
				}
				delete[] buf;
			}
		}
	}

	return S_OK;
}

void CALLBACK ep(_PEB* peb)
{
	MessageBoxW(0,
		peb->ProcessParameters->CommandLine.Buffer,
		peb->ProcessParameters->ImagePathName.Buffer,
		MB_OK|MB_ICONINFORMATION);
	ExitProcess(0);
}

BOOLEAN CALLBACK DllMain(PVOID DllHandle, DWORD Reason, PVOID ImageBaseAddress)
{
	if (DLL_PROCESS_ATTACH == Reason)
	{
		LdrDisableThreadCalloutsForDll(DllHandle);

		if (GetModuleHandleW(L"regsvr32.exe")) return TRUE;

		CONTEXT ctx = {};
		RtlCaptureContext(&ctx);

		_PEB* peb = RtlGetCurrentPeb(); // 2 parameter
		ImageBaseAddress = peb->ImageBaseAddress;

		if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(ImageBaseAddress))
		{
			(ULONG_PTR&)ImageBaseAddress += pinth->OptionalHeader.AddressOfEntryPoint; // 1 parameter

			if (PVOID Rip = GetProcAddress(GetModuleHandle(L"ntdll"), "RtlUserThreadStart"))
			{
				PNT_TIB Tib = reinterpret_cast<PNT_TIB>(NtCurrentTeb());
				union {
					PCONTEXT pctx;
					ULONG_PTR StackBase;
				};
				for (StackBase = (ULONG_PTR)Tib->StackBase - sizeof(CONTEXT);
					&ctx < pctx;
					StackBase -= __alignof(CONTEXT))
				{
					if (pctx->Rcx == (ULONG_PTR)ImageBaseAddress &&
						pctx->Rdx == (ULONG_PTR)peb &&
						pctx->Rip == (ULONG_PTR)Rip &&
						pctx->SegCs == ctx.SegCs &&
						pctx->SegSs == ctx.SegSs)
					{
						pctx->Rcx = (ULONG_PTR)ep;
						return TRUE;
					}
				}
			}
		}
	}

	return FALSE;
}

_NT_END