#pragma once
#include<windows.h>
#include <ImageHlp.h>
#pragma comment(lib,"dbghelp.lib")

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(ULONG SystemInformationClass,PVOID SystemInformation,ULONG Length,PULONG ReturnLength);
ZWQUERYSYSTEMINFORMATION g_ZwQuerySystemInformation = NULL;
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY{
	ULONG Unknow1;
	ULONG Unknow2;
	ULONG Unknow3;
	ULONG Unknow4;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _Module_INFO{
	char KernelName[MAX_PATH];
	char KernelPath[MAX_PATH];
	PVOID KernelBass;
	ULONG KernelSize;
}Module_INFO, * PModule_INFO;

typedef struct _SYMBOLS_DATA{
	PVOID NtCreateDebugObject;
	PVOID PsGetNextProcessThread;
	PVOID DbgkpPostFakeThreadMessages;
	PVOID DbgkpWakeTarget;
	PVOID DbgkpSetProcessDebugObject;
	PVOID DbgkCreateThread;
	PVOID DbgkpQueueMessage;
	PVOID PsCaptureExceptionPort;
	PVOID DbgkpSendApiMessage;
	PVOID DbgkpSendApiMessageLpc;
	PVOID DbgkpSendErrorMessage;
	PVOID DbgkForwardException;
	PVOID DbgkpSuppressDbgMsg;
	PVOID DbgkpSectionToFileHandle;
	PVOID DbgkUnMapViewOfSection;
	PVOID DbgkpPostFakeProcessCreateMessages;
	PVOID NtDebugActiveProcess;
	PVOID DbgkpMarkProcessPeb;
	PVOID KiDispatchException;
	PVOID NtCreateUserProcess;
	PVOID DbgkDebugObjectType;
	PVOID ObTypeIndexTable;
	PVOID NtTerminateProcess;
	PVOID DbgkMapViewOfSection;
	PVOID DbgkSendSystemDllMessages;
}SYMBOLS_DATA, * PSYMBOLS_DATA;
SYMBOLS_DATA g_SymbolsData = { 0 };
ULONG g_SymbolsDataSize = sizeof(SYMBOLS_DATA) / sizeof(PVOID);
typedef bool (*ENUMSYMBOLSCALLBACK)(char* Name, PVOID Address);

BOOLEAN GetKernelModuleInfo(PModule_INFO ModuleInfo)
{
	if (!ModuleInfo)
		return FALSE;

	NTSTATUS status;
	ULONG  RetLenth = 0;
	PSYSTEM_MODULE_INFORMATION Buffer = 0;

	do
	{
		Buffer = (PSYSTEM_MODULE_INFORMATION)malloc(RetLenth);
		if (!Buffer)
			return FALSE;
		status = g_ZwQuerySystemInformation(11, Buffer, RetLenth, &RetLenth);
		if (!NT_SUCCESS(status) && status != 0xC0000004L)
		{
			free(Buffer);
			return FALSE;
		}

	} while (status == 0xC0000004L);

	ModuleInfo->KernelBass = Buffer->Module[0].Base;
	ModuleInfo->KernelSize = Buffer->Module[0].Size;
	strcpy_s(ModuleInfo->KernelPath, Buffer->Module[0].ImageName);
	strcpy_s(ModuleInfo->KernelName, Buffer->Module[0].ImageName + Buffer->Module[0].ModuleNameOffset);
	free(Buffer);
	return TRUE;
}

BOOLEAN InitSymHandler()
{
	char Path[MAX_PATH] = { 0 };
	char FileName[MAX_PATH] = { 0 };
	char SymPath[MAX_PATH * 2] = { 0 };
	char SymbolsUrl[] = "http://msdl.microsoft.com/download/symbols";

	if (!GetCurrentDirectoryA(MAX_PATH, Path))
		return FALSE;

	//这里会生成一个symsrv.yes文件
	//strcat(Path, "\\Symbols");
	//CreateDirectoryA(Path, NULL);

	//strcpy(FileName, Path);
	//strcat(FileName, "\\symsrv.yes");
	//printf("%s \n", FileName);

	//HANDLE hfile = CreateFileA(FileName,FILE_ALL_ACCESS,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
	//if (hfile == INVALID_HANDLE_VALUE)
	//{
	//	printf("create or open file error: 0x%X \n", GetLastError());
	//	return FALSE;

	//}
	//CloseHandle(hfile);

	//https://learn.microsoft.com/zh-cn/windows/win32/api/dbghelp/nf-dbghelp-symsetoptions
	SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);//SYMOPT_DEBUG

	//SRV*c:\localsymbols*http://msdl.microsoft.com/download/symbols
	sprintf(SymPath, "SRV*%s*%s", Path, SymbolsUrl);

	if (!SymInitialize((HANDLE)-1, SymPath, TRUE))
		return FALSE;

	if (!SymSetSearchPath((HANDLE)-1, SymPath))
		return FALSE;

	return TRUE;
}

BOOLEAN EnumAllSymbolsCallBack(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext)
{
	return ((ENUMSYMBOLSCALLBACK)UserContext)(pSymInfo->Name, (PVOID)pSymInfo->Address);
}

BOOLEAN CallBack(char* Name, PVOID Address)
{
	if (strcmp(Name, "NtCreateDebugObject") == 0)
	{
		g_SymbolsData.NtCreateDebugObject = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsGetNextProcessThread") == 0)
	{
		g_SymbolsData.PsGetNextProcessThread = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpPostFakeThreadMessages") == 0)
	{
		g_SymbolsData.DbgkpPostFakeThreadMessages = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpWakeTarget") == 0)
	{
		g_SymbolsData.DbgkpWakeTarget = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSetProcessDebugObject") == 0)
	{
		g_SymbolsData.DbgkpSetProcessDebugObject = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkCreateThread") == 0)
	{
		g_SymbolsData.DbgkCreateThread = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpQueueMessage") == 0)
	{
		g_SymbolsData.DbgkpQueueMessage = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "PsCaptureExceptionPort") == 0)
	{
		g_SymbolsData.PsCaptureExceptionPort = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSendApiMessage") == 0)
	{
		g_SymbolsData.DbgkpSendApiMessage = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSendApiMessageLpc") == 0)
	{
		g_SymbolsData.DbgkpSendApiMessageLpc = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSendErrorMessage") == 0)
	{
		g_SymbolsData.DbgkpSendErrorMessage = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkForwardException") == 0)
	{
		g_SymbolsData.DbgkForwardException = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSuppressDbgMsg") == 0)
	{
		g_SymbolsData.DbgkpSuppressDbgMsg = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpSectionToFileHandle") == 0)
	{
		g_SymbolsData.DbgkpSectionToFileHandle = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkUnMapViewOfSection") == 0)
	{
		g_SymbolsData.DbgkUnMapViewOfSection = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpPostFakeProcessCreateMessages") == 0)
	{
		g_SymbolsData.DbgkpPostFakeProcessCreateMessages = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "NtDebugActiveProcess") == 0)
	{
		g_SymbolsData.NtDebugActiveProcess = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkpMarkProcessPeb") == 0)
	{
		g_SymbolsData.DbgkpMarkProcessPeb = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "KiDispatchException") == 0)
	{
		g_SymbolsData.KiDispatchException = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "NtCreateUserProcess") == 0)
	{
		g_SymbolsData.NtCreateUserProcess = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkDebugObjectType") == 0)
	{
		g_SymbolsData.DbgkDebugObjectType = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "ObTypeIndexTable") == 0)
	{
		g_SymbolsData.ObTypeIndexTable = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "NtTerminateProcess") == 0)
	{
		g_SymbolsData.NtTerminateProcess = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkMapViewOfSection") == 0)
	{
		g_SymbolsData.DbgkMapViewOfSection = Address;
		g_SymbolsDataSize--;
	}
	else if (strcmp(Name, "DbgkSendSystemDllMessages") == 0)
	{
		g_SymbolsData.DbgkSendSystemDllMessages = Address;
		g_SymbolsDataSize--;
	}
	if (g_SymbolsDataSize == 0)
	{
		return FALSE;
	}
	return TRUE;
}

BOOLEAN LoadSymbol()
{
	BOOLEAN isSuccess = FALSE;
	do
	{
		HMODULE hNtdll = GetModuleHandle("ntdll.dll");
		if (!hNtdll)
			break;
		g_ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtdll, "ZwQuerySystemInformation");
		if (!g_ZwQuerySystemInformation)
			break;
		Module_INFO Module = { 0 };
		GetKernelModuleInfo(&Module);
		if (!InitSymHandler())
			break;

		HMODULE hDll = LoadLibraryEx("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
		char SymFile1[MAX_PATH] = { "" };
		char szFile[MAX_PATH], SymFile[MAX_PATH] = { "" };
		GetModuleFileNameA(hDll, szFile, sizeof(szFile) / sizeof(szFile[0]));
		if (!SymGetSymbolFile((HANDLE)-1, NULL, szFile, sfPdb, SymFile, MAX_PATH, SymFile1, MAX_PATH))
			break;

		char FileName[MAX_PATH];
		GetSystemDirectoryA(FileName, sizeof(FileName));
		strcat_s(FileName, "\\");
		strcat_s(FileName, Module.KernelName);
		HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			break;

		DWORD dwfilesize = GetFileSize(hFile, NULL);
		DWORD64 BaseOfDll = SymLoadModule64((HANDLE)-1, hFile, FileName, NULL, (DWORD64)Module.KernelBass, dwfilesize);
		CloseHandle(hFile);
		if (!BaseOfDll)
			break;

		if (!SymEnumSymbols((HANDLE)-1, BaseOfDll, 0, (PSYM_ENUMERATESYMBOLS_CALLBACK)& EnumAllSymbolsCallBack, CallBack))
			break;
		isSuccess = TRUE;
	} while (FALSE);
	return isSuccess;
}