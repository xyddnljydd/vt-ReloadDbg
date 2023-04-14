#include"dbg.h"
#include"HookFunc.h"
#include"Lde.h"

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
extern PFAST_MUTEX DbgkpProcessDebugPortMutex;


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

HOOKLIST g_hookList[32] = { 0 };
ULONG g_count = 0;
VOID HookFunction(PVOID pFunc,PVOID hookAddress,PVOID *outAddress)
{
	PUCHAR   codePage = NULL;
	BOOLEAN  isSamePage = FALSE;
	for(ULONG i=0;i< g_count;i++)
	{
		if (PAGE_ALIGN(pFunc) == PAGE_ALIGN(g_hookList[i].pFunc) && g_hookList[i].codePage)
		{
			codePage = (PUCHAR)g_hookList[i].codePage;
			isSamePage = TRUE;
			break;
		}
	}

	PHYSICAL_ADDRESS phys = { 0 };
	phys.QuadPart = MAXULONG64;
	if(!codePage)
		codePage = (PUCHAR)MmAllocateContiguousMemory(PAGE_SIZE, phys);
	if (!codePage)
		return;

	if(!isSamePage)
		RtlCopyMemory(codePage, PAGE_ALIGN(pFunc), PAGE_SIZE);
	UCHAR JmpCode[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0";
	RtlCopyMemory(JmpCode + 2, &hookAddress, sizeof(ULONG64));
	ULONG_PTR PageOffset = (ULONG_PTR)pFunc - (ULONG_PTR)PAGE_ALIGN(pFunc);
	RtlCopyMemory(codePage + PageOffset, JmpCode, sizeof(JmpCode));

	ULONG HookSize = GetWriteCodeLen(pFunc, sizeof(JmpCode));
	*(PULONG64)(JmpCode + 2) = (ULONG64)pFunc + HookSize;
	ULONG64 OriFunc = (ULONG64)ExAllocatePoolWithTag(NonPagedPool, HookSize + sizeof(JmpCode), 'yc');
	if (OriFunc)
	{
		RtlCopyMemory((PVOID)OriFunc, pFunc, HookSize);
		RtlCopyMemory((PVOID)(OriFunc + HookSize), &JmpCode, sizeof(JmpCode));

		if (!isSamePage)
			g_hookList[g_count].codePage = codePage;

		g_hookList[g_count].pFunc = pFunc;
		g_hookList[g_count].orgFunc = (PVOID)OriFunc;

		*outAddress = (PVOID)OriFunc;
		g_count++;
	}
	else
		MmFreeContiguousMemory(codePage);
}

VOID ActiveHook()
{
	for (ULONG i = 0; i < g_count; i++)
	{
		if (g_hookList[i].codePage)
		{
			hv::hypercall_input Input = { 0 };
			Input.code = hv::hypercall_install_ept_hook;
			Input.key = hv::hypercall_key;
			Input.args[0] = MmGetPhysicalAddress(g_hookList[i].pFunc).QuadPart;
			Input.args[1] = MmGetPhysicalAddress(g_hookList[i].codePage).QuadPart;
			for (unsigned long i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
				auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);
				hv::vmx_vmcall(Input);
				KeRevertToUserAffinityThreadEx(orig_affinity);
			}
		}
	}


 }

VOID UnHookFunc(PVOID pFunc)
{
	hv::hypercall_input Input = { 0 };
	Input.code = hv::hypercall_remove_ept_hook;
	Input.key = hv::hypercall_key;
	Input.args[0] = MmGetPhysicalAddress(pFunc).QuadPart;
	for (unsigned long i = 0; i < KeQueryActiveProcessorCount(nullptr); ++i) {
		auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << i);
		hv::vmx_vmcall(Input);
		KeRevertToUserAffinityThreadEx(orig_affinity);
	}
}

void UnHookFreeAddress()
{
	for (ULONG i = 0; i < g_count; i++)
	{
		if (g_hookList[i].codePage)
		{
			UnHookFunc(g_hookList[i].pFunc);
			MmFreeContiguousMemory(g_hookList[i].codePage);
		}
		ExFreePool(g_hookList[i].orgFunc);
	}
	g_count = 0;
	memset(g_hookList,0,sizeof(HOOKLIST)*32);
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
	DbgkpProcessDebugPortMutex = (PFAST_MUTEX)g_SymbolsData.DbgkpProcessDebugPortMutex;
	
	//初始化调试对象的链表和锁
	InitializeListHead(&g_Debuginfo.List);
	KeInitializeSpinLock(&g_DebugLock);

	//这里开始hook函数==>被hook的函数不能在两个页面之间
	HookFunction(g_SymbolsData.DbgkCreateThread, DbgkCreateThread, (PVOID*)& OriginalDbgkCreateThread);
	HookFunction(g_SymbolsData.DbgkpQueueMessage, DbgkpQueueMessage, (PVOID*)& OriginalDbgkpQueueMessage);
	HookFunction(g_SymbolsData.NtTerminateProcess, NtTerminateProcess, (PVOID*)& OrignalNtTerminateProcess);
	HookFunction(g_SymbolsData.NtCreateUserProcess, NtCreateUserProcess, (PVOID*)& OrignalNtCreateUserProcess);
	HookFunction(g_SymbolsData.KiDispatchException, KiDispatchException, (PVOID*)& OrignalKiDispatchException);
	HookFunction(g_SymbolsData.NtCreateDebugObject, NtCreateDebugObject, (PVOID*)& OriginalNtCreateDebugObject);
	HookFunction(g_SymbolsData.NtDebugActiveProcess, NtDebugActiveProcess, (PVOID*)& OriginalNtDebugActiveProcess);
	HookFunction(g_SymbolsData.DbgkForwardException, DbgkForwardException, (PVOID*)& OriginalDbgkForwardException);
	HookFunction(g_SymbolsData.DbgkMapViewOfSection, DbgkMapViewOfSection, (PVOID*)& OriginalDbgkMapViewOfSection);
	HookFunction(g_SymbolsData.DbgkUnMapViewOfSection, DbgkUnMapViewOfSection, (PVOID*)& OriginalDbgkUnMapViewOfSection);
	HookFunction(g_SymbolsData.DbgkpSetProcessDebugObject, DbgkpSetProcessDebugObject, (PVOID*)& OriginalDbgkpSetProcessDebugObject);
	ActiveHook();

	if (!HookDbgkDebugObjectType())
		return FALSE;

	
	return TRUE;
}

BOOLEAN UnHookFuncs()
{
	UnHookFreeAddress();
	hv::stop();
	DbgPrint("[hv] Devirtualized the system.\n");
	DbgPrint("[hv] Driver unloaded.\n");
	return TRUE;
}