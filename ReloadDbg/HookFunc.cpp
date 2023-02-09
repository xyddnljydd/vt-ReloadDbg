#include"HookFunc.h"

extern SYMBOLS_DATA g_SymbolsData;
extern POBJECT_TYPE* g_DbgkDebugObjectType;

PFAST_MUTEX DbgkpProcessDebugPortMutex;

__DbgkpWakeTarget DbgkpWakeTarget = NULL;
__DbgkpSendApiMessage DbgkpSendApiMessage = NULL;
__DbgkpSuppressDbgMsg DbgkpSuppressDbgMsg = NULL;
__DbgkpMarkProcessPeb DbgkpMarkProcessPeb = NULL;
__DbgkCreateThread OriginalDbgkCreateThread = NULL;
__DbgkpSendErrorMessage DbgkpSendErrorMessage = NULL;
__NtTerminateProcess OrignalNtTerminateProcess = NULL;
__DbgkpSendApiMessageLpc DbgkpSendApiMessageLpc = NULL;
__PsCaptureExceptionPort PsCaptureExceptionPort = NULL;
__KiDispatchException OrignalKiDispatchException = NULL;
__NtCreateUserProcess OrignalNtCreateUserProcess = NULL;
__PsGetNextProcessThread  PsGetNextProcessThread = NULL;
__DbgkpSectionToFileHandle DbgkpSectionToFileHandle = NULL;
__DbgkSendSystemDllMessages DbgkSendSystemDllMessages = NULL;
__DbgkpPostFakeThreadMessages  DbgkpPostFakeThreadMessages = NULL;
__DbgkpPostFakeProcessCreateMessages DbgkpPostFakeProcessCreateMessages = NULL;

KSPIN_LOCK g_DebugLock = {};
DebugInfomation g_Debuginfo = { 0 };

#ifdef WIN7
#define  Thread_CrossThreadFlags 0x448
#define  Thread_RundownProtect 0x430
#define  Process_DebugPort 0x1f0
#define  Process_RundownProtect 0x178
#define  ProcessFlagS 0x440
#define  ProcessSectionObject 0x268
#define  ProcessSectionBaseAddress 0x270
#define  ThreadStartAddress 0x388
#else
#define  Thread_CrossThreadFlags 0x510
#define  Thread_RundownProtect 0x4f8
#define  Process_DebugPort 0x578
#define  Process_RundownProtect 0x458
#define  ProcessFlagS 0x464
#define  ProcessSectionObject 0x518
#define  ProcessSectionBaseAddress 0x520
#define  ThreadStartAddress 0x450
#endif

PVOID GetThread_CrossThreadFlags(PETHREAD EThread)
{
	return (PUCHAR)EThread + Thread_CrossThreadFlags;
}
PVOID GetThread_RundownProtect(PETHREAD EThread)
{
	return (PUCHAR)EThread + Thread_RundownProtect;
}
PVOID GetProcess_DebugPort(PEPROCESS EProcess)
{
	return (PUCHAR)EProcess + Process_DebugPort;
}
PVOID GetProcess_RundownProtect(PEPROCESS EProcess)
{
	return (PUCHAR)EProcess + Process_RundownProtect;
}
PVOID GetProcess_ProcessFlags(PEPROCESS EProcess)
{
	return (PUCHAR)EProcess + ProcessFlagS;
}
PVOID GetProcess_SectionObject(PEPROCESS EProcess)
{
	return (PUCHAR)EProcess + ProcessSectionObject;
}
PVOID GetProcess_SectionBaseAddress(PEPROCESS EProcess)
{
	return (PUCHAR)EProcess + ProcessSectionBaseAddress;
}
PVOID GetThread_StartAddress(PETHREAD EThread)
{
	return (PUCHAR)EThread + ThreadStartAddress;
}


NTSTATUS  NtCreateDebugObject(
	PHANDLE DebugObjectHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	ULONG Flags)
{
	NTSTATUS status;
	HANDLE Handle;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE	PreviousMode;

	PreviousMode = ExGetPreviousMode();

	_try{
		if (PreviousMode != KernelMode) {
			ProbeForWrite(DebugObjectHandle,sizeof(HANDLE),sizeof(UCHAR));
		}
		*DebugObjectHandle = NULL;

	} _except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}

	status = ObCreateObject(
		PreviousMode,
		*g_DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)& DebugObject);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}

	status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	_try{
		*DebugObjectHandle = Handle;
	} _except(ExSystemExceptionFilter()) {
		status = GetExceptionCode();
	}

	PDebugInfomation pDebuginfo = (PDebugInfomation)ExAllocatePoolWithTag(NonPagedPool, sizeof(DebugInfomation),'YC');
	if (pDebuginfo)
	{
		memset(pDebuginfo, 0, sizeof(DebugInfomation));

		pDebuginfo->SourceProcessId = PsGetCurrentProcessId();
		pDebuginfo->DebugObject = DebugObject;
		//pDebuginfo->DebugObjectHandle = Handle;

		KIRQL OldIrql = { 0 };
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		InsertTailList(&g_Debuginfo.List, &pDebuginfo->List);
		KeReleaseSpinLock(&g_DebugLock, OldIrql);
	}
	return status;
}


NTSTATUS DbgkpSetProcessDebugObject(
	PEPROCESS Process,
	PDEBUG_OBJECT DebugObject,
	NTSTATUS MsgStatus,
	PETHREAD LastThread)
{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;


	ThisThread = (PETHREAD)PsGetCurrentThread();
	InitializeListHead(&TempList);
	First = TRUE;
	GlobalHeld = FALSE;
	if (!NT_SUCCESS(MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	}
	else {
		Status = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(Status)) {
		while (TRUE) {

			////这里设置DebugPort，用来测试
			//PVOID DebugPort__ = GetProcess_DebugPort(Process);
			//*(ULONG64 *)(DebugPort__) = (ULONG64)DebugObject;
			ExAcquireFastMutex(DbgkpProcessDebugPortMutex);

			GlobalHeld = TRUE;
			ObfReferenceObject(LastThread);
			Thread = (PETHREAD)PsGetNextProcessThread((PEPROCESS)Process, (PETHREAD)LastThread);
			if (Thread != NULL) {

				ExReleaseFastMutex(DbgkpProcessDebugPortMutex);

				GlobalHeld = FALSE;
				ObfDereferenceObject(LastThread);
				Status = DbgkpPostFakeThreadMessages(
					Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status)) {
					LastThread = NULL;
					break;
				}
				ObfDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}
	ExAcquireFastMutex(&DebugObject->Mutex);
	if (NT_SUCCESS(Status)) {
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			ObfReferenceObject(DebugObject);
		}
		else {
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink;Entry != &DebugObject->EventList;) {
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == (PETHREAD)ThisThread) {
			Thread = DebugEvent->Thread;

			if (NT_SUCCESS(Status)) {
				if ((DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED) != 0) {
					PVOID CrossThreadFlags = GetThread_CrossThreadFlags(Thread);
					RtlInterlockedSetBitsDiscardReturn(CrossThreadFlags, 0x100);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PVOID CrossThreadFlags = GetThread_CrossThreadFlags(Thread);
					RtlInterlockedSetBitsDiscardReturn(CrossThreadFlags,0x80);
				}
			}
			else {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				PVOID RundownProtect = GetThread_RundownProtect(Thread);
				ExReleaseRundownProtection((PEX_RUNDOWN_REF)RundownProtect);
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld)
	{
		ExReleaseFastMutex(DbgkpProcessDebugPortMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

	//这里用来设置BeingDebugged的
	//if (NT_SUCCESS(Status)) {
	// DbgkpMarkProcessPeb(Process);
	//}

	return Status;
}


VOID  DbgkCreateThread(
	PETHREAD Thread)
{
	PVOID Port;
	DBGKM_APIMSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	PEPROCESS Process = PsGetCurrentProcess();
	HANDLE ProcessId = PsGetCurrentProcessId();
	PDBGKM_LOAD_DLL LoadDllArgs;
	NTSTATUS Status;
	OBJECT_ATTRIBUTES Obja;
	IO_STATUS_BLOCK IoStatusBlock;
	PIMAGE_NT_HEADERS NtHeaders;
	PTEB Teb;

	BOOLEAN isDebug = FALSE;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
	{
		PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
		if (pDebuginfo->TargetProcessId == PsGetCurrentProcessId() && pDebuginfo->TargetEPROCESS == PsGetCurrentProcess())
		{
			isDebug = TRUE;
			break;
		}
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);

	if (isDebug)
	{
		PVOID ProFlag = GetProcess_ProcessFlags(Process);
		ULONG OldFlags = RtlInterlockedSetBits(ProFlag, 0x400001);	//RtlInterlockedSetBits(&Process->Flags, 0x400001);之前这个bug在win7就会出现，屮找半天
		if ((OldFlags & PS_PROCESS_FLAGS_CREATE_REPORTED) == 0)
		{
			CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
			CreateThreadArgs->SubSystemKey = 0;

			CreateProcessArgs = &m.u.CreateProcessInfo;
			CreateProcessArgs->SubSystemKey = 0;
			CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle((PVOID)*(PULONG64)GetProcess_SectionObject(Process));
			CreateProcessArgs->BaseOfImage = (PVOID)*(PULONG64)GetProcess_SectionBaseAddress(Process);
			CreateThreadArgs->StartAddress = NULL;
			CreateProcessArgs->DebugInfoFileOffset = 0;
			CreateProcessArgs->DebugInfoSize = 0;

			__try
			{
				NtHeaders = RtlImageNtHeader((PVOID)*(PULONG64)GetProcess_SectionBaseAddress(Process));
				if (NtHeaders)
				{
					if (PsGetProcessWow64Process(Process) != NULL)
					{
						CreateThreadArgs->StartAddress = UlongToPtr(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, ImageBase) + DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER((PIMAGE_NT_HEADERS32)NtHeaders, AddressOfEntryPoint));
					}
					else {
						CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) + DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));
					}
					CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
					CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				CreateThreadArgs->StartAddress = NULL;
				CreateProcessArgs->DebugInfoFileOffset = 0;
				CreateProcessArgs->DebugInfoSize = 0;
			}

			m.h.u1.Length = 0x600038;
			m.h.u2.ZeroInit = 8;
			m.ApiNumber = DbgKmCreateProcessApi;

#ifdef WIN7
			DbgkpSendApiMessage(FALSE, &m);
#else
			DbgkpSendApiMessage(Process, FALSE, &m);
#endif
			
			if (CreateProcessArgs->FileHandle != NULL) {
				ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
			}
			DbgkSendSystemDllMessages(0, 0, &m);
		}
		else
		{
			CreateThreadArgs = &m.u.CreateThread;
			CreateThreadArgs->SubSystemKey = 0;
			CreateThreadArgs->StartAddress = (PVOID)*(PULONG64)GetThread_StartAddress(Thread);

			m.h.u1.Length = 0x400018;
			m.h.u2.ZeroInit = 8;
			m.ApiNumber = DbgKmCreateThreadApi;

#ifdef WIN7
			DbgkpSendApiMessage(TRUE, &m);
#else
			DbgkpSendApiMessage(Process, TRUE, &m);
#endif
			
		}
	}

	OriginalDbgkCreateThread(Thread);
}


NTSTATUS DbgkpQueueMessage(
	PEPROCESS Process,
	PETHREAD Thread,
	PDBGKM_APIMSG ApiMsg,
	ULONG Flags,
	PDEBUG_OBJECT TargetDebugObject)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT StaticDebugEvent;
	PDEBUG_OBJECT DebugObject = NULL;
	NTSTATUS Status;

	if (Flags & DEBUG_EVENT_NOWAIT)
	{
		DebugEvent = (PDEBUG_EVENT)ExAllocatePoolWithQuotaTag((POOL_TYPE)(NonPagedPool | POOL_QUOTA_FAIL_INSTEAD_OF_RAISE), sizeof(DEBUG_EVENT), 'EgbD');//sizeof (DEBUG_EVENT)=0x168
		if (!DebugEvent)
		{
			return  STATUS_INSUFFICIENT_RESOURCES;
		}

		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;//offset: 0x13
		ObReferenceObject(Thread);
		ObReferenceObject(Process);
		DebugObject = TargetDebugObject;
		DebugEvent->BackoutThread = PsGetCurrentThread();

	}
	else
	{
		DebugEvent = &StaticDebugEvent;
		DebugEvent->Flags = Flags;

		ExAcquireFastMutex(DbgkpProcessDebugPortMutex);

		KIRQL OldIrql = {0};
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
		{
			PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
			//if (pDebuginfo->SourceProcessId == PsGetCurrentProcessId() || pDebuginfo->TargetProcessId == PsGetCurrentProcessId())
			if(pDebuginfo->TargetProcessId == PsGetProcessId(Process) && pDebuginfo->TargetEPROCESS == Process)
			{
				DebugObject = pDebuginfo->DebugObject;
				break;
			}
		}
		KeReleaseSpinLock(&g_DebugLock, OldIrql);			 

		PVOID CrossThreadFlags = GetThread_CrossThreadFlags(Thread);
		if (ApiMsg->ApiNumber == DbgKmCreateThreadApi || ApiMsg->ApiNumber == DbgKmCreateProcessApi) {
			if (*(PULONG)(CrossThreadFlags) & PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG) {
				DebugObject = NULL;
			}
		}

		if (ApiMsg->ApiNumber == DbgKmExitThreadApi || ApiMsg->ApiNumber == DbgKmExitProcessApi) {
			if (*(PULONG)(CrossThreadFlags) & PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG) {
				DebugObject = NULL;
			}
		}
	}
	KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);

	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *ApiMsg;
	DebugEvent->ClientId.UniqueProcess = PsGetThreadProcessId(Thread);
	DebugEvent->ClientId.UniqueThread = PsGetThreadId(Thread);


	//KIRQL irql = KeGetCurrentIrql();//win7 这里可能会报irql bsod，那这里就直接返回
	if (DebugObject == NULL/* || irql >= APC_LEVEL*/)
	{
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		ExAcquireFastMutex(&DebugObject->Mutex);
		if ((DebugObject->Flags & DEBUG_OBJECT_DELETE_PENDING) == 0) {
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);

			if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
				KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
			}
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_DEBUGGER_INACTIVE;
		}
		ExReleaseFastMutex(&DebugObject->Mutex);
	}

	if ((Flags & DEBUG_EVENT_NOWAIT) == 0) {
		ExReleaseFastMutex(DbgkpProcessDebugPortMutex);

		if (NT_SUCCESS(Status)) {
			KeWaitForSingleObject(
				&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);
			Status = DebugEvent->Status;
			*ApiMsg = DebugEvent->ApiMsg;
		}
	}
	else {
		if (!NT_SUCCESS(Status)) {
			ObfDereferenceObject(Process);
			ObfDereferenceObject(Thread);
			ExFreePool(DebugEvent);
		}
	}

	return Status;
}


BOOLEAN  DbgkForwardException(
	PEXCEPTION_RECORD ExceptionRecord,
	BOOLEAN DebugException,
	BOOLEAN SecondChance)
{
	NTSTATUS		st;
	PEPROCESS		Process;
	PVOID			ExceptionPort;
	PDEBUG_OBJECT	DebugObject;
	BOOLEAN			bLpcPort;

	DBGKM_APIMSG m;
	PDBGKM_EXCEPTION args;

	DebugObject = NULL;
	ExceptionPort = NULL;
	bLpcPort = FALSE;

	args = &m.u.Exception;
	m.h.u1.Length = 0xD000A8;
	m.h.u2.ZeroInit = 8;
	m.ApiNumber = DbgKmExceptionApi;

	Process = (PEPROCESS)PsGetCurrentProcess();

	if (DebugException == TRUE)
	{
		KIRQL OldIrql = { 0 };
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
		{
			PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
			if (pDebuginfo->TargetProcessId == PsGetCurrentProcessId() && pDebuginfo->TargetEPROCESS == PsGetCurrentProcess())
			{
				DebugObject = pDebuginfo->DebugObject;
				break;
			}
		}
		KeReleaseSpinLock(&g_DebugLock, OldIrql);
	}
	else
	{
		ExceptionPort = PsCaptureExceptionPort(Process);
		m.h.u2.ZeroInit = 0x7;
		bLpcPort = TRUE;
	}

	if ((ExceptionPort == NULL && DebugObject == NULL) &&
		DebugException == TRUE)
	{
		return FALSE;
	}

	args->ExceptionRecord = *ExceptionRecord;
	args->FirstChance = !SecondChance;

	if (bLpcPort == FALSE)
	{
#ifdef WIN7
		st = DbgkpSendApiMessage(DebugException, &m);
#else
		st = DbgkpSendApiMessage(PsGetThreadProcess(KeGetCurrentThread()), DebugException, &m);
#endif
		 
	}
	else if (ExceptionPort) {

		st = DbgkpSendApiMessageLpc(&m, ExceptionPort, DebugException);
		ObfDereferenceObject(ExceptionPort);
	}
	else {
		m.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
		st = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(st))
	{

		st = m.ReturnedStatus;

		if (m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED)
		{
			if (DebugException == TRUE)
			{
				return FALSE;
			}

			st = DbgkpSendErrorMessage(ExceptionRecord, 0, &m);
		}
	}

	return NT_SUCCESS(st);
}


VOID DbgkMapViewOfSection(
	PEPROCESS	Process,
	PVOID SectionObject,
	PVOID BaseAddress
)
{
	PTEB	Teb;
	HANDLE	hFile;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS	CurrentProcess;
	PETHREAD	CurrentThread;
	PIMAGE_NT_HEADERS	pImageHeader;

	hFile = NULL;
	CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
	CurrentThread = (PETHREAD)PsGetCurrentThread();

	if (ExGetPreviousMode() == KernelMode)
		return;


	PDEBUG_OBJECT	DebugObject = NULL;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
	{
		PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
		if (pDebuginfo->TargetProcessId == PsGetCurrentProcessId() && pDebuginfo->TargetEPROCESS == PsGetCurrentProcess())
		{
			DebugObject = pDebuginfo->DebugObject;
			break;
		}
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);

	if (!DebugObject)
		return;

	Teb = (PTEB)PsGetThreadTeb(CurrentThread);

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			ApiMsg.u.LoadDll.NamePointer = Teb->NtTib.ArbitraryUserPointer;
		}
		else {
			return;
		}
	}
	else {
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}

	hFile = DbgkpSectionToFileHandle(SectionObject);
	ApiMsg.u.LoadDll.FileHandle = hFile;
	ApiMsg.u.LoadDll.BaseOfDll = BaseAddress;
	ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
	ApiMsg.u.LoadDll.DebugInfoSize = 0;

	_try{
		pImageHeader = RtlImageNtHeader(BaseAddress);
		if (pImageHeader != NULL)
		{
			ApiMsg.u.LoadDll.DebugInfoFileOffset = pImageHeader->FileHeader.PointerToSymbolTable;
			ApiMsg.u.LoadDll.DebugInfoSize = pImageHeader->FileHeader.NumberOfSymbols;
		}
	}_except(EXCEPTION_EXECUTE_HANDLER) {
		ApiMsg.u.LoadDll.DebugInfoFileOffset = 0;
		ApiMsg.u.LoadDll.DebugInfoSize = 0;
		ApiMsg.u.LoadDll.NamePointer = NULL;
	}
	ApiMsg.h.u1.Length = 0x500028;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmLoadDllApi;

#ifdef WIN7
	DbgkpSendApiMessage(0x1, &ApiMsg);
#else
	DbgkpSendApiMessage(PsGetThreadProcess(KeGetCurrentThread()), 0x1, &ApiMsg);
#endif

	if (ApiMsg.u.LoadDll.FileHandle != NULL)
	{
		ObCloseHandle(ApiMsg.u.LoadDll.FileHandle, KernelMode);
	}
}


VOID DbgkUnMapViewOfSection(
	PEPROCESS	Process,
	PVOID	BaseAddress)
{
	PTEB	Teb;
	DBGKM_APIMSG ApiMsg;
	PEPROCESS	CurrentProcess;
	PETHREAD	CurrentThread;

	CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
	CurrentThread = (PETHREAD)PsGetCurrentThread();

	if (ExGetPreviousMode() == KernelMode)
		return;

	PDEBUG_OBJECT	DebugObject = NULL;
	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
	{
		PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
		if (pDebuginfo->TargetProcessId == PsGetCurrentProcessId() && pDebuginfo->TargetEPROCESS == PsGetCurrentProcess())
		{
			DebugObject = pDebuginfo->DebugObject;
			break;
		}
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);

	if (!DebugObject)
		return;

	//这里省略了系统进程和挂靠进程的判断
	Teb = (PTEB)PsGetThreadTeb(CurrentThread);

	if (Teb != NULL && Process == CurrentProcess)
	{
		if (DbgkpSuppressDbgMsg(Teb))
		{
			return;
		}
	}
	ApiMsg.u.UnloadDll.BaseAddress = BaseAddress;
	ApiMsg.h.u1.Length = 0x380010;
	ApiMsg.h.u2.ZeroInit = 8;
	ApiMsg.ApiNumber = DbgKmUnloadDllApi;

#ifdef WIN7
	DbgkpSendApiMessage(0x1, &ApiMsg);
#else
	DbgkpSendApiMessage(PsGetThreadProcess(KeGetCurrentThread()), 0x1, &ApiMsg);
#endif
}


NTSTATUS  NtDebugActiveProcess(
	HANDLE ProcessHandle,
	HANDLE DebugObjectHandle)
{
	NTSTATUS status;
	KAPC_STATE	ApcState;
	KPROCESSOR_MODE PreviousMode;
	PDEBUG_OBJECT DebugObject;
	PEPROCESS Process, CurrentProcess;
	PETHREAD LastThread;
	PreviousMode = ExGetPreviousMode();
	status = ObReferenceObjectByHandle(
		ProcessHandle,
		0x800,
		*PsProcessType,
		PreviousMode,
		(PVOID*)& Process,
		NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	if (Process == (PEPROCESS)PsGetCurrentProcess() || Process == (PEPROCESS)PsInitialSystemProcess) {
		ObfDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	CurrentProcess = (PEPROCESS)PsGetCurrentProcess();
	status = ObReferenceObjectByHandle(
		DebugObjectHandle,
		0x2,
		*g_DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)& DebugObject,
		NULL);

	KIRQL OldIrql = { 0 };
	KeAcquireSpinLock(&g_DebugLock, &OldIrql);
	for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
	{
		PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
		if (pDebuginfo->SourceProcessId == PsGetCurrentProcessId())
		{
			DebugObject = pDebuginfo->DebugObject;
			pDebuginfo->TargetProcessId = PsGetProcessId(Process);
			pDebuginfo->TargetEPROCESS = Process;
			break;
		}
	}
	KeReleaseSpinLock(&g_DebugLock, OldIrql);

	if (NT_SUCCESS(status)) {

		PEX_RUNDOWN_REF RundownProtect = (PEX_RUNDOWN_REF)GetProcess_RundownProtect(Process);
		if (ExAcquireRundownProtection(RundownProtect))
		{
		status = DbgkpPostFakeProcessCreateMessages(Process, DebugObject, (PETHREAD*)& LastThread);
		status = DbgkpSetProcessDebugObject((PEPROCESS)Process, DebugObject, status, (PETHREAD)LastThread);
		ExReleaseRundownProtection(RundownProtect);
		}
		else {
		status = STATUS_PROCESS_IS_TERMINATING;
		}
	}

	ObfDereferenceObject(Process);

	return status;
}


VOID KiDispatchException(
	PEXCEPTION_RECORD ExceptionRecord,
	void* ExceptionFrame,
	PKTRAP_FRAME TrapFrame,
	KPROCESSOR_MODE PreviousMode,
	BOOLEAN FirstChance)
{
	if (PreviousMode != KernelMode)
	{
		BOOLEAN isDebug = FALSE;
		KIRQL OldIrql = { 0 };
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
		{
			PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
			if (pDebuginfo->TargetProcessId == PsGetCurrentProcessId() && pDebuginfo->TargetEPROCESS == PsGetCurrentProcess())
			{
				isDebug = TRUE;
				break;
			}
		}
		KeReleaseSpinLock(&g_DebugLock, OldIrql);

		if (isDebug)
		{
			if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
			{
				switch (ExceptionRecord->ExceptionCode)
				{
				case STATUS_BREAKPOINT:
					ExceptionRecord->ExceptionCode = STATUS_WX86_BREAKPOINT;
					break;
				case STATUS_SINGLE_STEP:
					ExceptionRecord->ExceptionCode = STATUS_WX86_SINGLE_STEP;
					break;
				}
			}

			if (DbgkForwardException(ExceptionRecord, TRUE, FALSE))
			{
				//int 2d 不返回，直接下发异常到异常处理
				if (*(PUSHORT)((ULONG64)(TrapFrame->Rip) - 3) != 0x2DCD)//int 2d
					return;
			}

			if ((TrapFrame->SegCs & 0xfff8) == KGDT64_R3_CMCODE)
			{
				switch (ExceptionRecord->ExceptionCode)
				{
				case STATUS_WX86_BREAKPOINT:
					ExceptionRecord->ExceptionCode = STATUS_BREAKPOINT;
					break;
				case STATUS_WX86_SINGLE_STEP:
					ExceptionRecord->ExceptionCode = STATUS_SINGLE_STEP;
					break;
				}
			}
		}
	}

	OrignalKiDispatchException(ExceptionRecord, ExceptionFrame, TrapFrame, PreviousMode, FirstChance);
	return;
}


NTSTATUS NtCreateUserProcess(
	PHANDLE ProcessHandle,
	PETHREAD ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	PVOID ProcessObjectAttributes,
	PVOID ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	PVOID ProcessParameters,
	void* CreateInfo,
	void* AttributeList)
{
	NTSTATUS status = 0;
	status = OrignalNtCreateUserProcess(ProcessHandle,
		ThreadHandle,
		ProcessDesiredAccess,
		ThreadDesiredAccess,
		ProcessObjectAttributes,
		ThreadObjectAttributes,
		ProcessFlags,
		ThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList);

	if (NT_SUCCESS(status) && ProcessHandle != NULL)
	{
		PDebugInfomation TmpDebuginfo = NULL;
		BOOLEAN isDebug = FALSE;
		KIRQL OldIrql = { 0 };
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
		{
			PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
			if (pDebuginfo->SourceProcessId == PsGetCurrentProcessId())
			{
				TmpDebuginfo = pDebuginfo;
				isDebug = TRUE;
				break;
			}
		}
		KeReleaseSpinLock(&g_DebugLock, OldIrql);

		if (isDebug)
		{
			PEPROCESS temp_process = NULL;
			status = ObReferenceObjectByHandle(*ProcessHandle, 0x0400, *PsProcessType, ExGetPreviousMode(), (void**)& temp_process, NULL);
			if (!NT_SUCCESS(status))
				return status;

			HANDLE target_pid = PsGetProcessId(temp_process);
			TmpDebuginfo->TargetProcessId = target_pid;
			TmpDebuginfo->TargetEPROCESS = temp_process;
			PVOID DebugPort__ = GetProcess_DebugPort(temp_process);
			*(ULONG64 *)(DebugPort__) = 0;
			DbgkpMarkProcessPeb(temp_process);

			PVOID Flags = GetProcess_ProcessFlags(temp_process);
			*(PULONG64)Flags &= ~PS_PROCESS_FLAGS_NO_DEBUG_INHERIT;

			return status;
		}
	}
	return status;
}


NTSTATUS NtTerminateProcess(
	HANDLE ProcessHandle,
	NTSTATUS ExitStatus)
{
	NTSTATUS st;
	PEPROCESS Process = NULL;
	if (ProcessHandle)
	{
		st = ObReferenceObjectByHandle(ProcessHandle,
			PROCESS_TERMINATE,
			*PsProcessType,
			ExGetPreviousMode(),
			(PVOID*)& Process,
			NULL);
	}
	else
	{
		Process = PsGetCurrentProcess();
	}

	if (Process)
	{
		KIRQL OldIrql = { 0 };
		KeAcquireSpinLock(&g_DebugLock, &OldIrql);
		for (PLIST_ENTRY pListEntry = g_Debuginfo.List.Flink; pListEntry != &g_Debuginfo.List; pListEntry = pListEntry->Flink)
		{
			PDebugInfomation pDebuginfo = CONTAINING_RECORD(pListEntry, DebugInfomation, List);
			if (pDebuginfo->TargetProcessId == PsGetProcessId(Process))
			{
				RemoveEntryList(&pDebuginfo->List);
				ExFreePool(pDebuginfo);
				break;
			}
		}
		KeReleaseSpinLock(&g_DebugLock, OldIrql);


		if (ProcessHandle)
			ObDereferenceObject(Process);
	}

	return OrignalNtTerminateProcess(ProcessHandle,ExitStatus);
}


