#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "KernelDbgStruct.h"

#define CTL_LOAD_DRIVER        0x800
#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef enum _JOBOBJECTINFOCLASS{
	JobObjectBasicAccountingInformation = 1,
	JobObjectBasicLimitInformation = 2,
	JobObjectBasicProcessIdList = 3,
	JobObjectBasicUIRestrictions = 4,
	JobObjectSecurityLimitInformation = 5,
	JobObjectEndOfJobTimeInformation = 6,
	JobObjectAssociateCompletionPortInformation = 7,
	JobObjectBasicAndIoAccountingInformation = 8,
	JobObjectExtendedLimitInformation = 9,
	JobObjectJobSetInformation = 10,
	JobObjectGroupInformation = 11,
	JobObjectNotificationLimitInformation = 12,
	JobObjectLimitViolationInformation = 13,
	JobObjectGroupInformationEx = 14,
	JobObjectCpuRateControlInformation = 15,
	JobObjectCompletionFilter = 16,
	JobObjectCompletionCounter = 17,
	JobObjectFreezeInformation = 18,
	JobObjectExtendedAccountingInformation = 19,
	JobObjectWakeInformation = 20,
	JobObjectBackgroundInformation = 21,
	JobObjectSchedulingRankBiasInformation = 22,
	JobObjectTimerVirtualizationInformation = 23,
	JobObjectCycleTimeNotification = 24,
	JobObjectClearEvent = 25,
	JobObjectReserved1Information = 18,
	JobObjectReserved2Information = 19,
	JobObjectReserved3Information = 20,
	JobObjectReserved4Information = 21,
	JobObjectReserved5Information = 22,
	JobObjectReserved6Information = 23,
	JobObjectReserved7Information = 24,
	JobObjectReserved8Information = 25,
	MaxJobObjectInfoClass = 26
}JOBOBJECTINFOCLASS;
enum vm_call_reasons {
	VMCALL_TEST,
	VMCALL_VMXOFF,
	VMCALL_EPT_HOOK_FUNCTION,
	VMCALL_EPT_UNHOOK_FUNCTION,
	VMCALL_INVEPT_CONTEXT,
	VMCALL_DUMP_POOL_MANAGER,
	VMCALL_DUMP_VMCS_STATE,
	VMCALL_HIDE_HV_PRESENCE,
	VMCALL_UNHIDE_HV_PRESENCE
};
enum invept_type {
	INVEPT_SINGLE_CONTEXT = 1,
	INVEPT_ALL_CONTEXTS = 2
};
typedef struct _SYMBOLS_DATA {
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


#ifdef WINVM

#else
extern "C" BOOLEAN __vm_call(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9);
extern "C" BOOLEAN __vm_call_ex(unsigned __int64 vmcall_reason, unsigned __int64 rdx, unsigned __int64 r8, unsigned __int64 r9, unsigned __int64 r10, unsigned __int64 r11, unsigned __int64 r12, unsigned __int64 r13, unsigned __int64 r14, unsigned __int64 r15);

extern "C" VOID NTAPI KeSignalCallDpcDone(PVOID SystemArgument1);
extern "C" BOOLEAN NTAPI KeSignalCallDpcSynchronize(PVOID SystemArgument2);
extern "C" VOID NTAPI KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, PVOID Context);

void vmoff();
BOOLEAN test_vmcall();
BOOLEAN unhook_all_functions();
void invept(BOOLEAN invept_all);
BOOLEAN send_irp_perform_allocation();
void hypervisor_visible(BOOLEAN value);
BOOLEAN unhook_function(unsigned __int64 function_address);
BOOLEAN hook_function(void* target_address, void* hook_function, void** origin_function);
void broadcast_vmoff(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
void broadcast_invept_all_contexts(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
BOOLEAN hook_function0(void* target_address, void* hook_function, void* trampoline_address, void** origin_function);
void broadcast_invept_single_context(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
#endif

extern "C" PVOID PsGetThreadTeb(PETHREAD Thread);
extern "C" LONG NTAPI ExSystemExceptionFilter(VOID);
extern "C" PVOID PsGetProcessWow64Process(PEPROCESS eprocess);
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
extern "C" NTKERNELAPI NTSTATUS ObCreateObjectType(PUNICODE_STRING TypeName, PVOID ObjectTypeInitializer, PSECURITY_DESCRIPTOR SecurityDescriptor, PVOID* ObjectType);
extern "C" NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode,POBJECT_TYPE ObjectType,POBJECT_ATTRIBUTES ObjectAttributes,KPROCESSOR_MODE OwnershipMode,PVOID ParseContext,ULONG ObjectBodySize,ULONG PagedPoolCharge,ULONG NonPagedPoolCharge,PVOID* Object);


