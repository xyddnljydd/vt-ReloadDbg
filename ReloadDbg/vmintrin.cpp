#include"vmintrin.h"

#ifdef WINVM

#else
void broadcast_vmoff(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(Dpc);

	__vm_call(VMCALL_VMXOFF, 0, 0, 0);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

void vmoff()
{
	KeGenericCallDpc(broadcast_vmoff, NULL);
}

void broadcast_invept_all_contexts(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(Dpc);

	__vm_call(VMCALL_INVEPT_CONTEXT, TRUE, 0, 0);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

void broadcast_invept_single_context(KDPC* Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(DeferredContext);
	UNREFERENCED_PARAMETER(Dpc);

	__vm_call(VMCALL_INVEPT_CONTEXT, TRUE, 0, 0);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}


BOOLEAN unhook_all_functions()
{
	return __vm_call(VMCALL_EPT_UNHOOK_FUNCTION, TRUE, 0, 0);
}

BOOLEAN unhook_function(unsigned __int64 function_address)
{
	return __vm_call(VMCALL_EPT_UNHOOK_FUNCTION, FALSE, function_address, 0);
}

void invept(BOOLEAN invept_all)
{
	if (invept_all == TRUE) KeGenericCallDpc(broadcast_invept_all_contexts, NULL);
	else KeGenericCallDpc(broadcast_invept_single_context, NULL);
}

void hypervisor_visible(BOOLEAN value)
{
	if (value == TRUE)
		__vm_call(VMCALL_UNHIDE_HV_PRESENCE, 0, 0, 0);
	else
		__vm_call(VMCALL_HIDE_HV_PRESENCE, 0, 0, 0);
}

BOOLEAN hook_function0(void* target_address, void* hook_function, void* trampoline_address, void** origin_function)
{
	BOOLEAN status = __vm_call_ex(VMCALL_EPT_HOOK_FUNCTION, (unsigned __int64)target_address, (unsigned __int64)hook_function, (unsigned __int64)trampoline_address, (unsigned __int64)origin_function, 0, 0, 0, 0, 0);
	invept(FALSE);

	return status;
}

BOOLEAN hook_function(void* target_address, void* hook_function, void** origin_function)
{
	BOOLEAN status = __vm_call_ex(VMCALL_EPT_HOOK_FUNCTION, (unsigned __int64)target_address, (unsigned __int64)hook_function, 0, (unsigned __int64)origin_function, 0, 0, 0, 0, 0);
	invept(FALSE);

	return status;
}

BOOLEAN test_vmcall()
{
	return __vm_call(VMCALL_TEST, 0, 0, 0);
}

BOOLEAN send_irp_perform_allocation()
{
	PDEVICE_OBJECT airhv_device_object;
	NTSTATUS status;
	KEVENT event;
	PIRP irp;
	IO_STATUS_BLOCK io_status = { 0 };
	UNICODE_STRING airhv_name;
	PFILE_OBJECT file_object;

	RtlInitUnicodeString(&airhv_name, L"\\Device\\HyperVisor");

	status = IoGetDeviceObjectPointer(&airhv_name, 0, &file_object, &airhv_device_object);

	ObReferenceObjectByPointer(airhv_device_object, FILE_ALL_ACCESS, 0, KernelMode);

	// We don't need this so we instantly dereference file object
	ObDereferenceObject(file_object);

	if (NT_SUCCESS(status) == FALSE)
	{
		//DbgPrint("Couldn't get hypervisor device object pointer");
		return FALSE;
	}

	KeInitializeEvent(&event, NotificationEvent, 0);
	irp = IoBuildDeviceIoControlRequest(IOCTL_POOL_MANAGER_ALLOCATE, airhv_device_object, 0, 0, 0, 0, 0, &event, &io_status);

	if (irp == NULL)
	{
		//DbgPrint("Couldn't create Irp");
		ObDereferenceObject(airhv_device_object);
		return FALSE;
	}

	else
	{
		status = IofCallDriver(airhv_device_object, irp);

		if (status == STATUS_PENDING)
			KeWaitForSingleObject(&event, Executive, KernelMode, 0, 0);

		ObDereferenceObject(airhv_device_object);
		return TRUE;
	}
}
#endif