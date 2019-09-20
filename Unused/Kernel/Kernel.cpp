//////////////////////////////////////////////////
// Kernel.cpp文件
#include "Head.h"

#define IOCTL_SETPROC  (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )
//#define IOCTL_KILL  (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )
#define NT_DRIVER_NAME L"\\Device\\MYDRIVER"
#define DOS_DRIVER_NAME L"\\??\\MYDRIVERDOS"

UNICODE_STRING DerName,DerName2;
PDEVICE_OBJECT	pDevObj;
PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
#define SYSCALL(_function)  KeServiceDescriptorTable->ServiceTable[ *(PULONG)((PUCHAR)_function+1)]

//StartService时调用
NTSTATUS DriverEntry( IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath )
{
	NTSTATUS status=STATUS_SUCCESS;
	int i = 0;
	for(i= 0;i<IRP_MJ_MAXIMUM_FUNCTION;++i) theDriverObject->MajorFunction[i] = DisPatchCreateClose;
	theDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DispatchDeviceControl;
	theDriverObject->DriverUnload=DriverUnload;
	RtlInitUnicodeString( &DerName, NT_DRIVER_NAME );
	status=IoCreateDevice(theDriverObject,0,&DerName,FILE_DEVICE_UNKNOWN,0,FALSE,&pDevObj);
	if(!NT_SUCCESS(status))
	{
		return status;
	}
	RtlInitUnicodeString( &DerName2, DOS_DRIVER_NAME );
	status=IoCreateSymbolicLink( &DerName2, &DerName );
	KeServiceDescriptorTable = (PSERVICE_DESCRIPTOR_TABLE)KernelGetProcAddress( KernelGetModuleBase( theDriverObject, "ntoskrnl.exe" ), "KeServiceDescriptorTable" );

//	DbgPrint("KeServiceDescriptorTable = %x\n",(ULONG)KeServiceDescriptorTable);

	return STATUS_SUCCESS;
}

NTSTATUS DisPatchCreateClose(PDEVICE_OBJECT pDriverObj,PIRP pIrp)
{
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//服务停止时执行
void DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	IoDeleteSymbolicLink(&DerName2);
	IoDeleteDevice(pDriverObj->DeviceObject);
}

//DeviceIoControl 时执行 
NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT  DeviceObject,IN PIRP  pIrp)
{
	__asm nop;
	NTSTATUS status=STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack=IoGetCurrentIrpStackLocation(pIrp);

	ULONG uIoControlCode=pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	PVOID pInputBuffer= pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
	PVOID pOutputBuffer=pIrp->UserBuffer;
	ULONG uInsize=pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG uOutsize=pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

//	DbgPrint("DispatchDeviceControl  Code:%X",uIoControlCode);
	switch(uIoControlCode)
	{
		__asm nop;
		case IOCTL_SETPROC:
		{
			ULONG uIndex = 0;
			PULONG pBase = NULL;

			uIndex = *(PULONG)pInputBuffer;
			if ( KeServiceDescriptorTable->NumberOfService <= uIndex )
			{
				status= STATUS_INVALID_PARAMETER;
				break;
			}

			pBase  = KeServiceDescriptorTable->ServiceTable;

//			DbgPrint("0x%x 0x%x",uIndex,*((PULONG)pOutputBuffer));
			__asm
			{//关中断
				nop
				nop
            	cli
				mov eax,cr0
				and eax,~0x10000
				mov cr0,eax
			}
			*( pBase + uIndex )=*((PULONG)pOutputBuffer);
			__asm
			{//开中断
				mov  eax,cr0
				or   eax,0x10000
				mov  cr0,eax
				sti
			}
			status=STATUS_SUCCESS;
		}
		break;
		case IOCTL_KILL:
			{
				if ( uInsize == sizeof(MYDATA) )
				{
					KillProcess((MYDATA*)pInputBuffer);
				}
			}
			break;
		default:
		break;
	}
	if(status==STATUS_SUCCESS)
		pIrp->IoStatus.Information=uOutsize;
	else
		pIrp->IoStatus.Information=0;
	
	pIrp->IoStatus.Status=status;
	IofCompleteRequest(pIrp,IO_NO_INCREMENT);
	return status;	
}

NTSTATUS KillProcess( MYDATA *data )
{
	NTSTATUS status = STATUS_SUCCESS;
	data->Pid ^= XorValue;
	if ( data->Pid == 0 ) return STATUS_UNSUCCESSFUL;
	PEPROCESS  process;

//	DbgPrint( "要结束的进程PID=%d", data->Pid );

	status = PsLookupProcessByProcessId( data->Pid, &process );
	if ( !NT_SUCCESS(status) )
	{
//		DbgPrint("PsLookupProcessByProcessId失败");
		return STATUS_UNSUCCESSFUL;
	}
	status = MmUnmapViewOfSection( process, data->ModuleAddress );
	if ( !NT_SUCCESS(status) )
	{
//		DbgPrint("MmUnmapViewOfSection失败");
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}
