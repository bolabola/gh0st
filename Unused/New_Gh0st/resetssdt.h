//#include <windows.h>
//#include <shlwapi.h>
//#include <winioctl.h>

#define IOCTL_SETPROC  (ULONG)CTL_CODE( FILE_DEVICE_UNKNOWN, 0x810, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )

#define RVATOVA(base,offset) ((PVOID)((DWORD)(base)+(DWORD)(offset)))
#define ibaseDD *(PDWORD)&ibase
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)


typedef struct {
	WORD    offset:12;
	WORD    type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;

typedef LONG NTSTATUS;

typedef NTSTATUS (WINAPI *PFNNtQuerySystemInformation)(    
	DWORD    SystemInformationClass,
	PVOID    SystemInformation,
	ULONG    SystemInformationLength,
	PULONG    ReturnLength
	);

typedef struct _SYSTEM_MODULE_INFORMATION {//Information Class 11
	ULONG    Reserved[2];
	PVOID    Base;
	ULONG    Size;
	ULONG    Flags;
	USHORT    Index;
	USHORT    Unknown;
	USHORT    LoadCount;
	USHORT    ModuleNameOffset;
	CHAR    ImageName[256];
}SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

typedef struct {
	DWORD    dwNumberOfModules;
	SYSTEM_MODULE_INFORMATION    smi;
} MODULES, *PMODULES;

//----------------------------------------------------------------
// stuff not found in header files
//----------------------------------------------------------------

typedef struct _UNICODE_STRING { 
    USHORT Length; 
    USHORT MaximumLength; 
#ifdef MIDL_PASS 
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer; 
#else // MIDL_PASS 
    PWSTR Buffer; 
#endif // MIDL_PASS 
} UNICODE_STRING, *PUNICODE_STRING; 

typedef long NTSTATUS; 

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0) 

typedef 
NTSTATUS 
(__stdcall *ZWSETSYSTEMINFORMATION)(
									DWORD SystemInformationClass, 
									PVOID SystemInformation, 
									ULONG SystemInformationLength
									);
typedef 
VOID 
(__stdcall *RTLINITUNICODESTRING)(
								  PUNICODE_STRING DestinationString, 
								  PCWSTR SourceString   
								  );

ZWSETSYSTEMINFORMATION ZwSetSystemInformation;
RTLINITUNICODESTRING RtlInitUnicodeString;

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE 
{ 
	UNICODE_STRING ModuleName; 
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE; 

#define SystemLoadAndCallImage 38

BOOL SetProc( IN HANDLE hDriver, IN ULONG ulIndex, IN PULONG buf )
{
    if ( NULL == buf )
    {
        return FALSE;
    }
    DWORD dwReturned;
    BOOL bRet = DeviceIoControl( hDriver, IOCTL_SETPROC, &ulIndex,sizeof( ULONG ), buf, sizeof( ULONG ), &dwReturned, NULL );
    return bRet && ERROR_SUCCESS == GetLastError();
}


DWORD GetHeaders(PCHAR ibase,
                PIMAGE_FILE_HEADER *pfh,
                PIMAGE_OPTIONAL_HEADER *poh,
                PIMAGE_SECTION_HEADER *psh)

{
    PIMAGE_DOS_HEADER mzhead=(PIMAGE_DOS_HEADER)ibase;
    
    if    ((mzhead->e_magic!=IMAGE_DOS_SIGNATURE) ||        
        (ibaseDD[mzhead->e_lfanew]!=IMAGE_NT_SIGNATURE))
        return FALSE;
    
    *pfh=(PIMAGE_FILE_HEADER)&ibase[mzhead->e_lfanew];
    if (((PIMAGE_NT_HEADERS)*pfh)->Signature!=IMAGE_NT_SIGNATURE) 
        return FALSE;
    *pfh=(PIMAGE_FILE_HEADER)((PBYTE)*pfh+sizeof(IMAGE_NT_SIGNATURE));
    
    *poh=(PIMAGE_OPTIONAL_HEADER)((PBYTE)*pfh+sizeof(IMAGE_FILE_HEADER));
    if ((*poh)->Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return FALSE;
    
    *psh=(PIMAGE_SECTION_HEADER)((PBYTE)*poh+sizeof(IMAGE_OPTIONAL_HEADER));
    return TRUE;
}


DWORD FindKiServiceTable(HMODULE hModule,DWORD dwKSDT)
{
    PIMAGE_FILE_HEADER    pfh;
    PIMAGE_OPTIONAL_HEADER    poh;
    PIMAGE_SECTION_HEADER    psh;
    PIMAGE_BASE_RELOCATION    pbr;
    PIMAGE_FIXUP_ENTRY    pfe;    
    
    DWORD    dwFixups=0,i,dwPointerRva,dwPointsToRva,dwKiServiceTable;
    BOOL    bFirstChunk;

    GetHeaders((PCHAR)hModule,&pfh,&poh,&psh);

    // loop thru relocs to speed up the search
    if ((poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) &&
        (!((pfh->Characteristics)&IMAGE_FILE_RELOCS_STRIPPED))) {
        
        pbr=(PIMAGE_BASE_RELOCATION)RVATOVA(poh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,hModule);

        bFirstChunk=TRUE;
        // 1st IMAGE_BASE_RELOCATION.VirtualAddress of ntoskrnl is 0
        while (bFirstChunk || pbr->VirtualAddress) {
            bFirstChunk=FALSE;

            pfe=(PIMAGE_FIXUP_ENTRY)((DWORD)pbr+sizeof(IMAGE_BASE_RELOCATION));

            for (i=0;i<(pbr->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))>>1;i++,pfe++) {
                if (pfe->type==IMAGE_REL_BASED_HIGHLOW) {
                    dwFixups++;
                    dwPointerRva=pbr->VirtualAddress+pfe->offset;
                    // DONT_RESOLVE_DLL_REFERENCES flag means relocs aren't fixed
                    dwPointsToRva=*(PDWORD)((DWORD)hModule+dwPointerRva)-(DWORD)poh->ImageBase;

                    // does this reloc point to KeServiceDescriptorTable.Base?
                    if (dwPointsToRva==dwKSDT) {
                        // check for mov [mem32],imm32. we are trying to find 
                        // "mov ds:_KeServiceDescriptorTable.Base, offset _KiServiceTable"
                        // from the KiInitSystem.
                        if (*(PWORD)((DWORD)hModule+dwPointerRva-2)==0x05c7) {
                            // should check for a reloc presence on KiServiceTable here
                            // but forget it
                            dwKiServiceTable=*(PDWORD)((DWORD)hModule+dwPointerRva+4)-poh->ImageBase;
                            return dwKiServiceTable;
                        }
                    }
                    
                } else
                    if (pfe->type!=IMAGE_REL_BASED_ABSOLUTE)
					{
                        // should never get here
                       // printf("\trelo type %d found at .%X\n",pfe->type,pbr->VirtualAddress+pfe->offset);
					}
            }
            *(PDWORD)&pbr+=pbr->SizeOfBlock;
        }
    }
    
    //if (!dwFixups) 
        // should never happen - nt, 2k, xp kernels have relocation data
       // printf("No fixups!\n");
    return 0;
}
/*
void ReSSDT( IN HANDLE hDriver)
{

}
*/