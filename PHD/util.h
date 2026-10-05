#pragma once

HRESULT GetLastHresult(ULONG dwError = GetLastError());

inline HRESULT GetLastHresult(BOOL fOk)
{
	return fOk ? S_OK : GetLastHresult();
}

template <typename T>
T HR(HRESULT& hr, T t)
{
	hr = t ? S_OK : GetLastHresult();
	return t;
}

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PVOID* ppb, _Out_ ULONG* pcb);