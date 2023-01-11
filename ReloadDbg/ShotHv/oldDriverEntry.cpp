#include "HvPch.h"

PVOID g_jmpNtQuerySystemInformation = NULL;

NTSTATUS HookNtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
) {

	using PNtQuerySystemInformation = NTSTATUS(*)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
		ULONG                    SystemInformationLength,
		PULONG                   ReturnLength
		);
	if (SystemInformationClass == SystemFirmwareTableInformation && SystemInformation)
	{
		__try
		{
			if (*(PULONG)SystemInformation == 0x4649524d || *(PULONG)SystemInformation == 0x52534d42)//MRIF BMSR
			{
				return STATUS_UNSUCCESSFUL;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
	}
	if(SystemInformationClass ==  SystemKernelDebuggerInformation || SystemInformationClass == SystemKernelDebuggerInformationEx || SystemCodeIntegrityInformation == SystemInformationClass || ProcessDebugObjectHandle == SystemInformationClass)
		return STATUS_UNSUCCESSFUL;

	return ((PNtQuerySystemInformation)g_jmpNtQuerySystemInformation)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

PVOID g_jmpNtQueryInformationProcess = NULL;
EXTERN_C NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
NTSTATUS HookNtQueryInformationProcess(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
) {

	using PNtQueryInformationProcess = NTSTATUS(*)(
		HANDLE           ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID            ProcessInformation,
		ULONG            ProcessInformationLength,
		PULONG           ReturnLength
		);
	
	UCHAR* fileName = PsGetProcessImageFileName(PsGetCurrentProcess());

	if (memcmp((const char*)fileName, "SuperKiller",strlen("SuperKiller")) == 0 && ExGetPreviousMode() == UserMode)//最新的3.6
	{

		if (ProcessInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ProcessInformation, ProcessInformationLength, 4);
				if (ReturnLength != 0)
					ProbeForWrite(ReturnLength, 4, 1);
			}

			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}


		if (ProcessInformationClass == ProcessDebugObjectHandle)
		{
			DbgPrint("HookNtQueryInformationProcess ProcessDebugObjectHandle \n");
			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x0400, *PsProcessType, UserMode, (PVOID*)& TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				__try
				{
					*(ULONG64*)ProcessInformation = NULL;
					if (ReturnLength != NULL)* ReturnLength = sizeof(ULONG64);

					Status = STATUS_PORT_NOT_SET;
				}

				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetProcess);
				return Status;
			}
			return Status;
		}


		else if (ProcessInformationClass == ProcessDebugPort)
		{
			DbgPrint("HookNtQueryInformationProcess ProcessDebugPort \n");
			if (ProcessInformationLength != sizeof(ULONG64))
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x0400, *PsProcessType, UserMode, (PVOID*)& TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				__try
				{
					*(ULONG64*)ProcessInformation = 0;
					if (ReturnLength != 0)
						* ReturnLength = sizeof(ULONG64);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetProcess);
				return Status;
			}
			return Status;
		}
		
		else if (ProcessInformationClass == ProcessDebugFlags)
		{
			DbgPrint("HookNtQueryInformationProcess ProcessDebugFlags \n");
			if (ProcessInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x0400, *PsProcessType, UserMode, (PVOID*)& TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				__try
				{
					*(ULONG*)ProcessInformation = 0;
					if (ReturnLength != 0)
						* ReturnLength = sizeof(ULONG);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetProcess);
				return Status;
			}

			return Status;
		}

		else if (ProcessInformationClass == ProcessBreakOnTermination)
		{
			DbgPrint("HookNtQueryInformationProcess ProcessBreakOnTermination \n");
			if (ProcessInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PEPROCESS TargetProcess;
			NTSTATUS Status = ObReferenceObjectByHandle(ProcessHandle, 0x1000, *PsProcessType, UserMode, (PVOID*)& TargetProcess, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				__try
				{
					*(ULONG*)ProcessInformation = 0;
					if (ReturnLength != 0)
						* ReturnLength = sizeof(ULONG);
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetProcess);
				return Status;
			}

			return Status;
		}
	}

	return ((PNtQueryInformationProcess)g_jmpNtQueryInformationProcess)(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

typedef struct _WOW64_FLOATING_SAVE_AREA
{
	ULONG ControlWord;
	ULONG StatusWord;
	ULONG TagWord;
	ULONG ErrorOffset;
	ULONG ErrorSelector;
	ULONG DataOffset;
	ULONG DataSelector;
	UCHAR RegisterArea[80];
	ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA, * PWOW64_FLOATING_SAVE_AREA;
typedef struct _WOW64_CONTEXT
{
	ULONG ContextFlags;

	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;

	WOW64_FLOATING_SAVE_AREA FloatSave;

	ULONG SegGs;
	ULONG SegFs;
	ULONG SegEs;
	ULONG SegDs;

	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;

	ULONG Ebp;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG Esp;
	ULONG SegSs;

	UCHAR ExtendedRegisters[512];

} WOW64_CONTEXT, * PWOW64_CONTEXT;
EXTERN_C PVOID NTAPI PsGetCurrentProcessWow64Process();
PVOID g_jmpNtQueryInformationThread = NULL;
NTSTATUS HookNtQueryInformationThread(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength,
	PULONG          ReturnLength
) {
	using PNtQueryInformationThread = NTSTATUS(*)(
		HANDLE          ThreadHandle,
		THREADINFOCLASS ThreadInformationClass,
		PVOID           ThreadInformation,
		ULONG           ThreadInformationLength,
		PULONG          ReturnLength
		);
	UCHAR* fileName = PsGetProcessImageFileName(PsGetCurrentProcess());

	if (memcmp((const char*)fileName, "SuperKiller", strlen("SuperKiller")) == 0 && ExGetPreviousMode() == UserMode)//最新的3.6
	{
		if (ThreadInformationLength != 0)
		{
			__try
			{
				ProbeForRead(ThreadInformation, ThreadInformationLength, 4);
				if (ReturnLength != 0)
					ProbeForWrite(ReturnLength, 4, 1);

			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				return GetExceptionCode();
			}
		}

		if (ThreadInformationClass == ThreadHideFromDebugger)
		{
			DbgPrint("HookNtQueryInformationThread ThreadHideFromDebugger \n");
			if (ThreadInformationLength != 1)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, 0x40, *PsThreadType, UserMode, (PVOID*)& TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				__try
				{
					*(BOOLEAN*)ThreadInformation =0;

					if (ReturnLength != 0)* ReturnLength = 1;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetThread);
				return Status;
			}

			return Status;
		}

	/*	if (ThreadInformationClass == ThreadBreakOnTermination)
		{
			DbgPrint("HookNtQueryInformationThread ThreadBreakOnTermination \n");
			if (ThreadInformationLength != 4)
				return STATUS_INFO_LENGTH_MISMATCH;

			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, 0x40, *PsThreadType, UserMode, (PVOID*)& TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{

				__try
				{
					*(ULONG*)ThreadInformation = 0;

					if (ReturnLength != NULL)* ReturnLength = 4;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetThread);
				return Status;
			}

			return Status;
		}

		if (ThreadInformationClass == ThreadWow64Context)
		{
			DbgPrint("HookNtQueryInformationThread ThreadInformationClass \n");
			PETHREAD TargetThread;
			NTSTATUS Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_GET_CONTEXT, *PsThreadType, UserMode, (PVOID*)& TargetThread, NULL);
			if (NT_SUCCESS(Status) == TRUE)
			{
				if (ThreadInformationLength != sizeof(WOW64_CONTEXT))
				{
					ObDereferenceObject(TargetThread);
					return STATUS_INFO_LENGTH_MISMATCH;
				}

				PVOID WoW64Process = PsGetCurrentProcessWow64Process();
				if (WoW64Process == 0)
				{
					ObDereferenceObject(TargetThread);
					return STATUS_INVALID_PARAMETER;
				}

				__try
				{
					PWOW64_CONTEXT Context = (PWOW64_CONTEXT)ThreadInformation;
					ULONG OriginalFlags = Context->ContextFlags;

					Context->ContextFlags &= ~0x10;

					Status = ((PNtQueryInformationThread)g_jmpNtQueryInformationThread)(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

					if (OriginalFlags & 0x10)
					{
						Context->ContextFlags |= 0x10;
						RtlSecureZeroMemory(&Context->Dr0, sizeof(ULONG) * 6);
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					Status = GetExceptionCode();
				}

				ObDereferenceObject(TargetThread);
				return Status;
			}

			return Status;
		}

*/


	}
	return ((PNtQueryInformationThread)g_jmpNtQueryInformationThread)(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}



VOID
WINAPI
DetourHooks()
{
	UNICODE_STRING NtQuerySystemInformationString = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");
	PVOID Address = MmGetSystemRoutineAddress(&NtQuerySystemInformationString);
	auto ntStatus = PHHook(Address, HookNtQuerySystemInformation, &g_jmpNtQuerySystemInformation);

	UNICODE_STRING NtQueryInformationProcessString = RTL_CONSTANT_STRING(L"NtQueryInformationProcess");
	PVOID Address2 = MmGetSystemRoutineAddress(&NtQueryInformationProcessString);
	ntStatus = PHHook(Address2, HookNtQueryInformationProcess, &g_jmpNtQueryInformationProcess);

	UNICODE_STRING NtQueryInformationThreadString = RTL_CONSTANT_STRING(L"NtQueryInformationThread");
	PVOID Address3 = MmGetSystemRoutineAddress(&NtQueryInformationThreadString);
	ntStatus = PHHook(Address3, HookNtQueryInformationThread, &g_jmpNtQueryInformationThread);
	if (NT_SUCCESS(ntStatus))
		PHActivateHooks();

	return;
}


NTSTATUS 
WINAPI
ShotHvShutDown(
	_In_ PDEVICE_OBJECT DeviceObject, 
	_In_ PIRP Irp
){
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);

	DisableIntelVT();

	// IRP相关处理
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//VOID 
//WINAPI
//DriverUnload(
//	_In_ PDRIVER_OBJECT DriverObject
//){
//	UNREFERENCED_PARAMETER(DriverObject);
//	
//	DisableIntelVT();
//
//	UnRegisterShutdownCallBack();
//
//	UnInitKernelComm(DriverObject);
//}
//
//
//NTSTATUS 
//WINAPI
//DriverEntry(
//	_In_ PDRIVER_OBJECT DriverObject, 
//	_In_ PUNICODE_STRING RegisterPath
//){
//	UNREFERENCED_PARAMETER(DriverObject);
//	UNREFERENCED_PARAMETER(RegisterPath);
//	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
//
//	NTSTATUS ntStatus = STATUS_SUCCESS;
//	DriverObject->DriverUnload = DriverUnload;
//	
//	// 注册关机回调
//	ntStatus = RegisterShutdownCallBack(ShotHvShutDown);
//	if (!NT_SUCCESS(ntStatus)) {
//		return ntStatus;
//	}
//
//	// 开启 HV
//	ntStatus = EnableIntelVT();
//	if (!NT_SUCCESS(ntStatus)) {
//		return ntStatus;
//	}
//
//	//*KdDebuggerNotPresent = FALSE;
//	//*KdDebuggerEnabled = FALSE;
//
//	//SharedUserData->KdDebuggerEnabled  = FALSE;
//	ntStatus = InitKernelComm(DriverObject);
//	//DetourHooks();
//
//	return ntStatus;
//}