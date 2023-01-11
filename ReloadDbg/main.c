#include "ShotHv/HvPch.h"
#include"dbg.h"

SYMBOLS_DATA g_SymbolsData = { 0 };

NTSTATUS VmTest()
{
	__try 
	{
		if (!test_vmcall())
			return STATUS_UNSUCCESSFUL;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT  DriverObject)
{

	UnHookFuncs();

	if (DriverObject->DeviceObject)
	{
		UNICODE_STRING DosDeviceName;
		RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\YCData");
		IoDeleteSymbolicLink(&DosDeviceName);
		IoDeleteDevice(DriverObject->DeviceObject);
	}

	return STATUS_SUCCESS;
}

NTSTATUS DrvComm(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvIOCTLDispatcher(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;

	switch (Stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case CTL_CODE(FILE_DEVICE_UNKNOWN, CTL_LOAD_DRIVER, METHOD_BUFFERED, FILE_ANY_ACCESS):
		{
			__try
			{
				memmove(&g_SymbolsData, Irp->AssociatedIrp.SystemBuffer, sizeof(SYMBOLS_DATA));
				DbgInit();
				
			}_except(EXCEPTION_EXECUTE_HANDLER){}
			break;
		}

	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PCUNICODE_STRING Reg)
{
	UNREFERENCED_PARAMETER(Reg);
	Driver->DriverUnload = DriverUnload;

	if(NT_SUCCESS(VmTest()))
	{
		PDEVICE_OBJECT DeviceObject;
		UNICODE_STRING DriverName, DosDeviceName;
		RtlInitUnicodeString(&DriverName, L"\\Device\\YCData");
		RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\YCData");

		IoCreateDevice(Driver, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

		Driver->MajorFunction[IRP_MJ_CLOSE] = DrvComm;
		Driver->MajorFunction[IRP_MJ_CREATE] = DrvComm;
		Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIOCTLDispatcher;
		Driver->Flags |= DO_BUFFERED_IO;

		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}

	return STATUS_SUCCESS;
}