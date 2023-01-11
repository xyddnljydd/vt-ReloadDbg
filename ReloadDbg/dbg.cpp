#include"dbg.h"
#include"HookFunc.h"


extern SYMBOLS_DATA g_SymbolsData;
extern __DbgkpWakeTarget DbgkpWakeTarget;
extern __DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg;
extern __DbgkpMarkProcessPeb DbgkpMarkProcessPeb;
extern __DbgkpSendApiMessage DbgkpSendApiMessage;
extern __DbgkCreateThread OriginalDbgkCreateThread;
extern __DbgkpSendErrorMessage DbgkpSendErrorMessage;
extern  __NtTerminateProcess OrignalNtTerminateProcess;
extern __DbgkpSendApiMessageLpc DbgkpSendApiMessageLpc;
extern __PsCaptureExceptionPort PsCaptureExceptionPort;
extern __PsGetNextProcessThread  PsGetNextProcessThread;
extern __KiDispatchException OrignalKiDispatchException;
extern __NtCreateUserProcess OrignalNtCreateUserProcess;
extern __DbgkpSectionToFileHandle DbgkpSectionToFileHandle;
extern __DbgkSendSystemDllMessages DbgkSendSystemDllMessages;
extern __DbgkpPostFakeThreadMessages  DbgkpPostFakeThreadMessages;
extern __DbgkpPostFakeProcessCreateMessages DbgkpPostFakeProcessCreateMessages;


extern KSPIN_LOCK g_DebugLock;
extern DebugInfomation g_Debuginfo;


PVOID 	OriginalDbgkpQueueMessage = NULL;
PVOID 	OriginalNtCreateDebugObject = NULL;
PVOID 	OriginalDbgkForwardException = NULL;
PVOID   OriginalNtDebugActiveProcess = NULL;
PVOID   OriginalDbgkMapViewOfSection = NULL;
PVOID 	OriginalDbgkUnMapViewOfSection = NULL;
PVOID 	OriginalDbgkpSetProcessDebugObject = NULL;

POBJECT_TYPE* g_DbgkDebugObjectType;
BOOLEAN HookDbgkDebugObjectType()
{
	ULONG64 addr = 0;
	ULONG templong = 0;
	UNICODE_STRING ObjectTypeName;

	g_DbgkDebugObjectType = (POBJECT_TYPE*)g_SymbolsData.DbgkDebugObjectType;
	if (g_DbgkDebugObjectType == 0)
		return FALSE;

	RtlInitUnicodeString(&ObjectTypeName, L"YCData");
	OBJECT_TYPE_INITIALIZER_WIN10 ObjectTypeInitializer;
	POBJECT_TYPE* DbgkDebugObjectType = g_DbgkDebugObjectType;
	memcpy(&ObjectTypeInitializer, &(*DbgkDebugObjectType)->TypeInfo, sizeof(OBJECT_TYPE_INITIALIZER_WIN10));

	//这里恢复调试权限
	ObjectTypeInitializer.DeleteProcedure = NULL;
	ObjectTypeInitializer.CloseProcedure = NULL;
	ObjectTypeInitializer.GenericMapping.GenericRead = 0x00020001;
	ObjectTypeInitializer.GenericMapping.GenericWrite = 0x00020002;
	ObjectTypeInitializer.GenericMapping.GenericExecute = 0x00120000;
	ObjectTypeInitializer.GenericMapping.GenericAll = 0x001f000f;
	ObjectTypeInitializer.ValidAccessMask = 0x001f000f;

	NTSTATUS status = ObCreateObjectType(&ObjectTypeName, &ObjectTypeInitializer, NULL, (PVOID*)g_DbgkDebugObjectType);

	if (!NT_SUCCESS(status))
	{
		if (status == STATUS_OBJECT_NAME_COLLISION)
		{
			POBJECT_TYPE* ObTypeIndexTable = (POBJECT_TYPE*)g_SymbolsData.ObTypeIndexTable;
			if (!ObTypeIndexTable)
				return FALSE;

			ULONG Index = 2;
			while (ObTypeIndexTable[Index])
			{
				if (&ObTypeIndexTable[Index]->Name)
				{
					if (ObTypeIndexTable[Index]->Name.Buffer)
					{
						if (RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &ObjectTypeName, FALSE) == 0)
						{
							*g_DbgkDebugObjectType = ObTypeIndexTable[Index];
							return TRUE;
						}
					}
				}

				Index++;
			}
		}
	}

	return TRUE;
}

/*
	win7-win10下
	会用到debugport的函数
	PsGetProcessDebugPort       //获取debugport的值，不处理
	DbgkpSetProcessDebugObject  //这里不将debugport的值写到eprocess的debugport字段，也不调用DbgkpMarkProcessPeb
	DbgkpMarkProcessPeb         //DbgkClearProcessDebugObject、DbgkpCloseObject（objectType的CloseProcedure，这里直接不实现）和DbgkpSetProcessDebugObject中会调用
	DbgkCreateThread            //简单实现内部有点长,不实现线程回调
	PspExitThread         	    //不实现，不要线程退出消息
	DbgkExitThread      		//PspExitThread会调用DbgkExitThread，上面都不实现
	DbgkpQueueMessage			//实现比较简单
	KiDispatchException   		//可以不实现，但内核调试器会先捕获到异常需要gn，不方便内核调试,而且不处理过不了int 2d
	DbgkForwardException		//调用了三个原函数
	NtQueryInformationProcess 	//不处理
	DbgkClearProcessDebugObject //不实现 
	DbgkpCloseObject            //不实现  
	DbgkMapViewOfSection		//调用了两个原函数
	DbgkUnMapViewOfSection		//调用了两个原函数
	DbgkExitProcess				//不实现
*/

BOOLEAN DbgInit()
{
	//初始化函数	
	DbgkpWakeTarget = (__DbgkpWakeTarget)g_SymbolsData.DbgkpWakeTarget;
	DbgkpSuppressDbgMsg = (__DbgkpSuppressDbgMsg)g_SymbolsData.DbgkpSuppressDbgMsg;
	DbgkpSendApiMessage = (__DbgkpSendApiMessage)g_SymbolsData.DbgkpSendApiMessage;
	DbgkpMarkProcessPeb = (__DbgkpMarkProcessPeb)g_SymbolsData.DbgkpMarkProcessPeb;
	DbgkpSendErrorMessage = (__DbgkpSendErrorMessage)g_SymbolsData.DbgkpSendErrorMessage;
	PsGetNextProcessThread = (__PsGetNextProcessThread)g_SymbolsData.PsGetNextProcessThread;
	DbgkpSendApiMessageLpc = (__DbgkpSendApiMessageLpc)g_SymbolsData.DbgkpSendApiMessageLpc;
	PsCaptureExceptionPort = (__PsCaptureExceptionPort)g_SymbolsData.PsCaptureExceptionPort;
	DbgkpSectionToFileHandle = (__DbgkpSectionToFileHandle)g_SymbolsData.DbgkpSectionToFileHandle;
	DbgkSendSystemDllMessages = (__DbgkSendSystemDllMessages)g_SymbolsData.DbgkSendSystemDllMessages;
	DbgkpPostFakeThreadMessages = (__DbgkpPostFakeThreadMessages)g_SymbolsData.DbgkpPostFakeThreadMessages;
	DbgkpPostFakeProcessCreateMessages = (__DbgkpPostFakeProcessCreateMessages)g_SymbolsData.DbgkpPostFakeProcessCreateMessages;
	
	//初始化调试对象的链表和锁
	InitializeListHead(&g_Debuginfo.List);
	KeInitializeSpinLock(&g_DebugLock);

	//这里开始hook函数
#ifdef WINVM
	PHHook(g_SymbolsData.DbgkCreateThread, DbgkCreateThread, (PVOID*)&OriginalDbgkCreateThread);
	PHHook(g_SymbolsData.DbgkpQueueMessage, DbgkpQueueMessage, (PVOID*)&OriginalDbgkpQueueMessage);
	PHHook(g_SymbolsData.NtTerminateProcess, NtTerminateProcess, (PVOID*)&OrignalNtTerminateProcess);
	PHHook(g_SymbolsData.NtCreateUserProcess, NtCreateUserProcess, (PVOID*)&OrignalNtCreateUserProcess);
	PHHook(g_SymbolsData.KiDispatchException, KiDispatchException, (PVOID*)&OrignalKiDispatchException);
	PHHook(g_SymbolsData.NtCreateDebugObject, NtCreateDebugObject, (PVOID*)&OriginalNtCreateDebugObject);
	PHHook(g_SymbolsData.NtDebugActiveProcess, NtDebugActiveProcess, (PVOID*)&OriginalNtDebugActiveProcess);
	PHHook(g_SymbolsData.DbgkForwardException, DbgkForwardException, (PVOID*)&OriginalDbgkForwardException);
	PHHook(g_SymbolsData.DbgkMapViewOfSection, DbgkMapViewOfSection, (PVOID*)&OriginalDbgkMapViewOfSection);
	PHHook(g_SymbolsData.DbgkUnMapViewOfSection, DbgkUnMapViewOfSection, (PVOID*)&OriginalDbgkUnMapViewOfSection);
	PHHook(g_SymbolsData.DbgkpSetProcessDebugObject, DbgkpSetProcessDebugObject, (PVOID*)&OriginalDbgkpSetProcessDebugObject);
	PHActivateHooks();
#else
	hook_function(g_SymbolsData.DbgkCreateThread, DbgkCreateThread, (PVOID*)&OriginalDbgkCreateThread);
	hook_function(g_SymbolsData.DbgkpQueueMessage, DbgkpQueueMessage, (PVOID*)&OriginalDbgkpQueueMessage);
	hook_function(g_SymbolsData.NtTerminateProcess, NtTerminateProcess, (PVOID*)&OrignalNtTerminateProcess);
	hook_function(g_SymbolsData.NtCreateUserProcess, NtCreateUserProcess, (PVOID*)&OrignalNtCreateUserProcess);
	hook_function(g_SymbolsData.KiDispatchException, KiDispatchException, (PVOID*)&OrignalKiDispatchException);
	hook_function(g_SymbolsData.NtCreateDebugObject, NtCreateDebugObject, (PVOID*)&OriginalNtCreateDebugObject);
	hook_function(g_SymbolsData.NtDebugActiveProcess, NtDebugActiveProcess, (PVOID*)&OriginalNtDebugActiveProcess);
	hook_function(g_SymbolsData.DbgkForwardException, DbgkForwardException, (PVOID*)&OriginalDbgkForwardException);
	hook_function(g_SymbolsData.DbgkMapViewOfSection, DbgkMapViewOfSection, (PVOID*)&OriginalDbgkMapViewOfSection);
	hook_function(g_SymbolsData.DbgkUnMapViewOfSection, DbgkUnMapViewOfSection, (PVOID*)&OriginalDbgkUnMapViewOfSection);
	hook_function(g_SymbolsData.DbgkpSetProcessDebugObject, DbgkpSetProcessDebugObject, (PVOID*)&OriginalDbgkpSetProcessDebugObject);
#endif

	if (!HookDbgkDebugObjectType())
		return FALSE;

	
	return TRUE;
}


BOOLEAN UnHookFuncs()
{
#ifdef WINVM
	DisableIntelVT();
#else
	unhook_all_functions();
#endif
	
	return TRUE;
}