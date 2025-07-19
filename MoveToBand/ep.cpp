#include "stdafx.h"

_NT_BEGIN

enum ZBID
{
	ZBID_DEFAULT = 0,
	ZBID_DESKTOP = 1,
	ZBID_UIACCESS = 2,
	ZBID_IMMERSIVE_IHM = 3,
	ZBID_IMMERSIVE_NOTIFICATION = 4,
	ZBID_IMMERSIVE_APPCHROME = 5,
	ZBID_IMMERSIVE_MOGO = 6,
	ZBID_IMMERSIVE_EDGY = 7,
	ZBID_IMMERSIVE_INACTIVEMOBODY = 8,
	ZBID_IMMERSIVE_INACTIVEDOCK = 9,
	ZBID_IMMERSIVE_ACTIVEMOBODY = 10,
	ZBID_IMMERSIVE_ACTIVEDOCK = 11,
	ZBID_IMMERSIVE_BACKGROUND = 12,
	ZBID_IMMERSIVE_SEARCH = 13,
	ZBID_GENUINE_WINDOWS = 14,
	ZBID_IMMERSIVE_RESTRICTED = 15,
	ZBID_SYSTEM_TOOLS = 16,

	//Windows 10+
	ZBID_LOCK = 17,
	ZBID_ABOVELOCK_UX = 18
};

EXTERN_C
WINUSERAPI
HWND
WINAPI
CreateWindowInBand(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam,
	_In_opt_ ZBID dwBand);

EXTERN_C
WINUSERAPI
HWND
WINAPI
SetWindowBand(HWND hWnd, _In_opt_ ZBID dwBand);

EXTERN_C PVOID __imp_CreateWindowInBand = 0;

EXTERN_C extern ULONG_PTR __imp_CreateWindowExW;

ULONG WINAPI fgm(PVOID hmod)
{
	Sleep(1000);
	FreeLibraryAndExitThread((HMODULE)hmod, 0);
}

PVOID _G_Handler;
ULONG _G_dwThreadId;

HWND
WINAPI
HookCreateWindow(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCWSTR lpClassName,
	_In_opt_ LPCWSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam)
{
	ZBID dwBand = ZBID_DEFAULT;

	if (!hWndParent && !((WS_POPUP | WS_CHILD) & dwStyle))
	{
		dwBand = ZBID_ABOVELOCK_UX;

		RtlRemoveVectoredExceptionHandler(_G_Handler);

		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ctx.Dr7 = 0x400;
		ctx.Dr3 = 0;
		ZwSetContextThread(NtCurrentThread(), &ctx);

		NtClose(CreateThread(0, 0, fgm, &__ImageBase, 0, 0));
	}

	return CreateWindowInBand(dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y,
		nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam, dwBand);
}

LONG NTAPI VEH(::PEXCEPTION_POINTERS ExceptionInfo)
{
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
	if (STATUS_SINGLE_STEP == ExceptionRecord->ExceptionCode && GetCurrentThreadId() == _G_dwThreadId)
	{
		::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;
		if ((ULONG_PTR)ExceptionRecord->ExceptionAddress == ContextRecord->Dr3)
		{
			ContextRecord->Rip = (ULONG_PTR)HookCreateWindow;

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

BOOLEAN DoHook()
{
	if (_G_Handler = RtlAddVectoredExceptionHandler(TRUE, VEH))
	{
		_G_dwThreadId = GetCurrentThreadId();

		CONTEXT ctx = {};
		RtlCaptureContext(&ctx);
		ctx.Rdx = (ULONG_PTR)RtlGetCurrentPeb();
		PNT_TIB Tib = reinterpret_cast<PNT_TIB>(NtCurrentTeb());
		union {
			PCONTEXT pctx;
			ULONG_PTR StackBase;
		};
		for (StackBase = (ULONG_PTR)Tib->StackBase - sizeof(CONTEXT);
			&ctx < pctx;
			StackBase -= __alignof(CONTEXT))
		{
			if (pctx->Rdx == ctx.Rdx &&
				pctx->SegCs == ctx.SegCs && pctx->SegSs == ctx.SegSs &&
				pctx->R8 == 0x8888888888888888 && pctx->R9 == 0x9999999999999999)
			{
				pctx->ContextFlags |= CONTEXT_DEBUG_REGISTERS;
				pctx->Dr7 = 0x440;
				pctx->Dr3 = __imp_CreateWindowExW;
				return TRUE;
			}
		}

		RtlRemoveVectoredExceptionHandler(_G_Handler);
	}

	return FALSE;
}

BOOLEAN NTAPI DllMain(PVOID ImageBase, DWORD dwReason, PVOID ) 
{ 
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
		LdrDisableThreadCalloutsForDll(ImageBase);
		if (__imp_CreateWindowInBand = GetProcAddress(GetModuleHandleW(L"user32"), "CreateWindowInBand"))
		{
			return DoHook();
		}
	}
	return FALSE;
}

_NT_END