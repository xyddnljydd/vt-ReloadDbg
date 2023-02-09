#pragma once
#include "vmintrin.h"

#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
            ((hdrs)->OptionalHeader.##field)
typedef struct _DebugInfomation{
	LIST_ENTRY List;
	HANDLE SourceProcessId;
	HANDLE TargetProcessId;
	//HANDLE DebugObjectHandle;
	PVOID TargetEPROCESS;
	DEBUG_OBJECT* DebugObject;
}DebugInfomation,*PDebugInfomation;


typedef VOID(*__DbgkCreateThread)(PETHREAD Thread);
typedef VOID(*__DbgkpWakeTarget)(PDEBUG_EVENT DebugEvent);
typedef PVOID(*__PsCaptureExceptionPort)(PEPROCESS Process);
typedef PETHREAD(*__PsGetNextProcessThread)(PEPROCESS  Process, PETHREAD Thread);
typedef NTSTATUS(*__DbgkpPostFakeThreadMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD StartThread, PETHREAD* pFirstThread, PETHREAD* pLastThread);



#ifdef WIN7
typedef NTSTATUS(*__DbgkpSendApiMessage)(BOOLEAN SuspendProcess, PDBGKM_APIMSG ApiMsg);
#else
typedef NTSTATUS(*__DbgkpSendApiMessage)(PEPROCESS Process, BOOLEAN SuspendProcess, PDBGKM_APIMSG ApiMsg);
#endif

typedef BOOLEAN(*__DbgkpSuppressDbgMsg)(PVOID teb);
typedef VOID(*__DbgkpMarkProcessPeb)(PEPROCESS Process);
typedef HANDLE(*__DbgkpSectionToFileHandle)(PVOID SectionObject);
typedef NTSTATUS(*__NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(*__DbgkpSendApiMessageLpc)(PDBGKM_APIMSG ApiMsg, PVOID Port, BOOLEAN SuspendProcess);
typedef VOID(*__DbgkSendSystemDllMessages)(PETHREAD Thread, PDEBUG_OBJECT	DebugObject, PDBGKM_APIMSG ApiMsg);
typedef NTSTATUS(*__DbgkpSendErrorMessage)(PEXCEPTION_RECORD ExceptionRecord, ULONG Falge, PDBGKM_APIMSG DbgApiMsg);
typedef NTSTATUS(*__DbgkpPostFakeProcessCreateMessages)(PEPROCESS Process, PDEBUG_OBJECT DebugObject, PETHREAD* pLastThread);
typedef VOID(*__KiDispatchException)(PEXCEPTION_RECORD ExceptionRecord, void* ExceptionFrame, void* TrapFrame, KPROCESSOR_MODE PreviousMode, BOOLEAN FirstChance);
typedef NTSTATUS(*__NtCreateUserProcess)(PHANDLE ProcessHandle, PETHREAD ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PVOID ProcessObjectAttributes, PVOID ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, void* CreateInfo, void* AttributeList);

VOID  DbgkCreateThread(PETHREAD Thread);
VOID DbgkUnMapViewOfSection(PEPROCESS	Process, PVOID	BaseAddress);
NTSTATUS NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
NTSTATUS  NtDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
VOID DbgkMapViewOfSection(PEPROCESS	Process, PVOID SectionObject, PVOID BaseAddress);
BOOLEAN  DbgkForwardException(PEXCEPTION_RECORD ExceptionRecord, BOOLEAN DebugException, BOOLEAN SecondChance);
NTSTATUS  DbgkpSetProcessDebugObject(PEPROCESS Process, PDEBUG_OBJECT DebugObject, NTSTATUS MsgStatus, PETHREAD LastThread);
NTSTATUS DbgkpQueueMessage(PEPROCESS Process, PETHREAD Thread, PDBGKM_APIMSG ApiMsg, ULONG Flags, PDEBUG_OBJECT TargetDebugObject);
NTSTATUS  NtCreateDebugObject(PHANDLE DebugObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags);
VOID KiDispatchException(PEXCEPTION_RECORD ExceptionRecord,void* ExceptionFrame,PKTRAP_FRAME TrapFrame,KPROCESSOR_MODE PreviousMode,BOOLEAN FirstChance);
NTSTATUS NtCreateUserProcess(PHANDLE ProcessHandle,PETHREAD ThreadHandle,ACCESS_MASK ProcessDesiredAccess,ACCESS_MASK ThreadDesiredAccess,PVOID ProcessObjectAttributes,PVOID ThreadObjectAttributes,ULONG ProcessFlags,ULONG ThreadFlags,PVOID ProcessParameters,void* CreateInfo, void* AttributeList);