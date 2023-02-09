#include<stdio.h>
#include"symbols.h"

HANDLE g_DeviceHandle = NULL;
bool SetPrivilegeA(const LPCSTR lpszPrivilege, const BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = nullptr;
	LUID luid = { 0,0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (!LookupPrivilegeValueA(nullptr, lpszPrivilege, &luid)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(hToken, false, &priv, 0, nullptr, nullptr)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (hToken)
		CloseHandle(hToken);
	return true;
}
int openProcExp()
{
	SetPrivilegeA(SE_DEBUG_NAME, TRUE);
	if (!g_DeviceHandle)
		g_DeviceHandle = CreateFile("\\\\.\\YCData", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (g_DeviceHandle == INVALID_HANDLE_VALUE)
	{
		g_DeviceHandle = NULL;
		printf("OpenFailed YCData \n");
		return 0;
	}
	return 1;
}

void closeProcExp()
{
	CloseHandle(g_DeviceHandle);
}

void sendData(ULONG IoCtl, PVOID inData, ULONG inLen, PVOID outData, ULONG outLne)
{
	DWORD ReturnLength = 0;
	BOOL IsOk = DeviceIoControl(
		g_DeviceHandle,
		IoCtl,
		inData,
		inLen,
		outData,
		outLne,
		&ReturnLength,
		NULL);
}

#define CTL_LOAD_DRIVER        0x800
int main()
{
	if (LoadSymbol())
	{
		printf("load Success!\n");
		printf("g_SymbolsData.NtCreateDebugObject %p \n", g_SymbolsData.NtCreateDebugObject);
		printf("g_SymbolsData.DbgkpProcessDebugPortMutex %p \n", g_SymbolsData.DbgkpProcessDebugPortMutex);
		if (openProcExp())
		{
			sendData(CTL_CODE(FILE_DEVICE_UNKNOWN, CTL_LOAD_DRIVER, METHOD_BUFFERED, FILE_ANY_ACCESS), &g_SymbolsData, sizeof(SYMBOLS_DATA), NULL, NULL);
			closeProcExp();
		}
	}

	system("pause");
}