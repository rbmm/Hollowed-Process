#include "stdafx.h"

_NT_BEGIN

ULONG _tls_index;

void NTAPI ep2(_PEB* peb)
{
	ExitProcess(MessageBoxW(0,
		peb->ProcessParameters->CommandLine.Buffer,
		peb->ProcessParameters->ImagePathName.Buffer,
		MB_OK | MB_ICONINFORMATION));
}

void CALLBACK OnTls(PVOID DllHandle, DWORD Reason, PVOID Rip)
{
	if (DLL_PROCESS_ATTACH == Reason)
	{
		CONTEXT ctx = {};
		RtlCaptureContext(&ctx);

		_PEB* peb = RtlGetCurrentPeb(); // 2 parameter

		if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(DllHandle = peb->ImageBaseAddress))
		{
			(ULONG_PTR&)DllHandle += pinth->OptionalHeader.AddressOfEntryPoint; // 1 parameter

			if (Rip = GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlUserThreadStart"))
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
					if (pctx->Rcx == (ULONG_PTR)DllHandle &&
						pctx->Rdx == (ULONG_PTR)peb &&
						pctx->Rip == (ULONG_PTR)Rip &&
						pctx->SegCs == ctx.SegCs &&
						pctx->SegSs == ctx.SegSs)
					{
						pctx->Rcx = (ULONG_PTR)ep2;
						break;
					}
				}
			}
		}
	}
}
static const PIMAGE_TLS_CALLBACK g_tls_cb[] = { OnTls, 0 };

#pragma const_seg(".rdata$T")

EXTERN_C const IMAGE_TLS_DIRECTORY _tls_used = {
	(ULONG_PTR)0,			// start of tls data
	(ULONG_PTR)0,			// end of tls data
	(ULONG_PTR)&_tls_index,	// address of tls_index
	(ULONG_PTR)g_tls_cb,	// pointer to call back array
};
#pragma const_seg()

#ifdef _WIN64
__pragma(comment(linker, "/include:_tls_used"))
#else 
__pragma(comment(linker, "/include:__tls_used"))
#endif

void WINAPI ep(void*)
{
	ExitProcess(0);
}

_NT_END