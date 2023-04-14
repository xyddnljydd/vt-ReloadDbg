#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include "KernelDbgStruct.h"

#define CTL_LOAD_DRIVER        0x800
#define IOCTL_POOL_MANAGER_ALLOCATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
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
	PVOID DbgkpProcessDebugPortMutex;
}SYMBOLS_DATA, * PSYMBOLS_DATA;

extern "C" PVOID PsGetThreadTeb(PETHREAD Thread);
extern "C" LONG NTAPI ExSystemExceptionFilter(VOID);
extern "C" PVOID PsGetProcessWow64Process(PEPROCESS eprocess);
extern "C" PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
extern "C" NTKERNELAPI NTSTATUS ObCreateObjectType(PUNICODE_STRING TypeName, PVOID ObjectTypeInitializer, PSECURITY_DESCRIPTOR SecurityDescriptor, PVOID* ObjectType);
extern "C" NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode,POBJECT_TYPE ObjectType,POBJECT_ATTRIBUTES ObjectAttributes,KPROCESSOR_MODE OwnershipMode,PVOID ParseContext,ULONG ObjectBodySize,ULONG PagedPoolCharge,ULONG NonPagedPoolCharge,PVOID* Object);


