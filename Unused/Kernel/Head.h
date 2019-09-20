extern "C"
{
	#include <ntddk.h>
}
#include "ntimage.h"
#include <WinDef.h>
#include "../Public.h"
#include <wchar.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation, // 0 Y N
	SystemProcessorInformation, // 1 Y N
	SystemPerformanceInformation, // 2 Y N
	SystemTimeOfDayInformation, // 3 Y N
	SystemNotImplemented1, // 4 Y N
	SystemProcessesAndThreadsInformation, // 5 Y N
	SystemCallCounts, // 6 Y N
	SystemConfigurationInformation, // 7 Y N
	SystemProcessorTimes, // 8 Y N
	SystemGlobalFlag, // 9 Y Y
	SystemNotImplemented2, // 10 Y N
	SystemModuleInformation, // 11 Y N
	SystemLockInformation, // 12 Y N
	SystemNotImplemented3, // 13 Y N
	SystemNotImplemented4, // 14 Y N
	SystemNotImplemented5, // 15 Y N
	SystemHandleInformation, // 16 Y N
	SystemObjectInformation, // 17 Y N
	SystemPagefileInformation, // 18 Y N
	SystemInstructionEmulationCounts, // 19 Y N
	SystemInvalidInfoClass1, // 20
	SystemCacheInformation, // 21 Y Y
	SystemPoolTagInformation, // 22 Y N
	SystemProcessorStatistics, // 23 Y N
	SystemDpcInformation, // 24 Y Y
	SystemNotImplemented6, // 25 Y N
	SystemLoadImage, // 26 N Y
	SystemUnloadImage, // 27 N Y
	SystemTimeAdjustment, // 28 Y Y
	SystemNotImplemented7, // 29 Y N
	SystemNotImplemented8, // 30 Y N
	SystemNotImplemented9, // 31 Y N
	SystemCrashDumpInformation, // 32 Y N
	SystemExceptionInformation, // 33 Y N
	SystemCrashDumpStateInformation, // 34 Y Y/N
	SystemKernelDebuggerInformation, // 35 Y N
	SystemContextSwitchInformation, // 36 Y N
	SystemRegistryQuotaInformation, // 37 Y Y
	SystemLoadAndCallImage, // 38 N Y
	SystemPrioritySeparation, // 39 N Y
	SystemNotImplemented10, // 40 Y N
	SystemNotImplemented11, // 41 Y N
	SystemInvalidInfoClass2, // 42
	SystemInvalidInfoClass3, // 43
	SystemTimeZoneInformation, // 44 Y N
	SystemLookasideInformation, // 45 Y N
	SystemSetTimeSlipEvent, // 46 N Y
	SystemCreateSession, // 47 N Y
	SystemDeleteSession, // 48 N Y
	SystemInvalidInfoClass4, // 49
	SystemRangeStartInformation, // 50 Y N
	SystemVerifierInformation, // 51 Y Y
	SystemAddVerifier, // 52 N Y
	SystemSessionProcessesInformation // 53 Y N
}SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
/*
typedef struct _MYDATA
{
	ULONG Pid;
	ULONG ModuleAddress;
}MYDATA;
*/
NTSTATUS DisPatchCreateClose(PDEVICE_OBJECT pDriverObj,PIRP pIrp);
NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT  DeviceObject,IN PIRP  pIrp);
void DriverUnload(PDRIVER_OBJECT pDriverObj);
NTSTATUS KillProcess( MYDATA *data );

typedef struct _SERVICE_DESCRIPTOR_TABLE 
{ 
	PULONG	ServiceTable; 
	PULONG	ServiceCounterTable; 
	ULONG	NumberOfService; 
	ULONG	ParamTableBase; 
}SERVICE_DESCRIPTOR_TABLE,*PSERVICE_DESCRIPTOR_TABLE;

typedef NTSTATUS (*pNtQuerySystemInformation)
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation,
	ULONG SystemInformationLength, 
	PULONG ReturnLength OPTIONAL
);
/*
DWORD GetFunctionAddr(IN PCWSTR FunctionName)
{
    UNICODE_STRING UniCodeFunctionName;
    RtlInitUnicodeString( &UniCodeFunctionName, FunctionName );
	return (DWORD)MmGetSystemRoutineAddress( &UniCodeFunctionName );
}
*/
extern "C"
{
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId( ULONG	UniqueProcessId, PEPROCESS	*Process ); 
NTSTATUS MmUnmapViewOfSection( PEPROCESS Process, ULONG BaseAddress );
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation, 
	ULONG SystemInformationLength, 
	PULONG ReturnLength OPTIONAL 
);
PVOID RtlImageDirectoryEntryToData(
								   IN PVOID Base,
								   IN BOOLEAN MappedAsImage,
								   IN USHORT DirectoryEntry,
								   OUT PULONG Size);
};

PLIST_ENTRY g_LoadOrderListHead = NULL;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY     LoadOrder;
    LIST_ENTRY     MemoryOrder;
    LIST_ENTRY     InitializationOrder;
    PVOID          ModuleBaseAddress;
    PVOID          EntryPoint;
    ULONG          ModuleSize;
    UNICODE_STRING FullModuleName;
    UNICODE_STRING ModuleName;
    ULONG          Flags;
    USHORT         LoadCount;
    USHORT         TlsIndex;
    union {
        LIST_ENTRY Hash;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG   TimeStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

PVOID KernelGetModuleBase( PDRIVER_OBJECT DriverObject, PCHAR pModuleName )
{
    PVOID pModuleBase = NULL;
    PLIST_ENTRY Next;
    PLIST_ENTRY LoadOrderListHead;
    UNICODE_STRING uStr;
    PLDR_DATA_TABLE_ENTRY LdrDataTableEntry;
    PLDR_DATA_TABLE_ENTRY LdrDataTableEntry0;
    ULONG len;
    BOOLEAN FreeUstr = FALSE;
	
    uStr.Buffer = NULL;

    __try
    {
        if(!g_LoadOrderListHead) {
            LdrDataTableEntry0 = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
			
            uStr.Length = sizeof(L"NTOSKRNL.EXE")-sizeof(WCHAR);
            uStr.MaximumLength = sizeof(L"NTOSKRNL.EXE");
            uStr.Buffer = L"NTOSKRNL.EXE";

            Next = LdrDataTableEntry0->LoadOrder.Blink;
            while ( TRUE ) {
                LdrDataTableEntry = CONTAINING_RECORD( Next,
					LDR_DATA_TABLE_ENTRY,
					LoadOrder
					);
                Next = Next->Blink;
                if(!LdrDataTableEntry->ModuleName.Buffer) {
                    return NULL;
                }
                if(RtlCompareUnicodeString(&LdrDataTableEntry->ModuleName, &uStr, TRUE) == 0)
                {
                    LoadOrderListHead = Next;
                    break;
                }
                if(LdrDataTableEntry == LdrDataTableEntry0)
                    return NULL;
            }
            g_LoadOrderListHead = LoadOrderListHead;
        } else {
            LoadOrderListHead = g_LoadOrderListHead;
        }
        len = strlen(pModuleName);
        if(!len)
            return NULL;
        len = (len+1)*sizeof(WCHAR);
		
        uStr.MaximumLength = (USHORT)len;
        uStr.Length = (USHORT)len - sizeof(WCHAR);
        uStr.Buffer = (PWCHAR)ExAllocatePool(NonPagedPool, len);
        FreeUstr = TRUE;
        swprintf(uStr.Buffer, L"%S", pModuleName);
		
        Next = LoadOrderListHead->Flink;
        while ( Next != LoadOrderListHead ) {
            LdrDataTableEntry = CONTAINING_RECORD( Next,
				LDR_DATA_TABLE_ENTRY,
				LoadOrder
				);
            if(RtlCompareUnicodeString(&LdrDataTableEntry->ModuleName, &uStr, TRUE) == 0)
            {
                pModuleBase = LdrDataTableEntry->ModuleBaseAddress;
                break;
            }
            Next = Next->Flink;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        pModuleBase = NULL;
    }
    if(FreeUstr && uStr.Buffer) {
        ExFreePool(uStr.Buffer);
    }
	
    return pModuleBase;
} // end KernelGetModuleBase()

PVOID KernelGetProcAddress( PVOID ModuleBase, PCHAR pFunctionName )
{
    PVOID pFunctionAddress = NULL;
    __try
    {

        ULONG                 size = 0;
        PIMAGE_EXPORT_DIRECTORY exports =(PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
        ULONG addr = /*(PUCHAR)*/((ULONG)exports-(ULONG)ModuleBase);
        PULONG functions =(PULONG)((ULONG) ModuleBase + exports->AddressOfFunctions);
        PSHORT ordinals  =(PSHORT)((ULONG) ModuleBase + exports->AddressOfNameOrdinals);
        PULONG names     =(PULONG)((ULONG) ModuleBase + exports->AddressOfNames);
        ULONG  max_name  =exports->NumberOfNames;
        ULONG  max_func  =exports->NumberOfFunctions;
        ULONG i;
        for (i = 0; i < max_name; i++)
        {
            ULONG ord = ordinals[i];
            if(i >= max_name || ord >= max_func) {
                return NULL;
            }
            if (functions[ord] < addr || functions[ord] >= addr + size)
            {
                if (strcmp((PCHAR) ModuleBase + names[i], pFunctionName)  == 0)
                {
                    pFunctionAddress =(PVOID)((PCHAR) ModuleBase + functions[ord]);
                    break;
                }
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        pFunctionAddress = NULL;
    }
	
    return pFunctionAddress;
} // end KernelGetProcAddress()
