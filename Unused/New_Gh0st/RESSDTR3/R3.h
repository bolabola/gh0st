// common.h: interface for the common class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_COMMON_H__26B16518_B067_46E6_9E85_7DBF1D1DBB5D__INCLUDED_)
#define AFX_COMMON_H__26B16518_B067_46E6_9E85_7DBF1D1DBB5D__INCLUDED_

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <aclapi.h>

#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH	((NTSTATUS)0xC0000004L)
#define OBJ_CASE_INSENSITIVE		0x00000040L
#define PAGE_READONLY				0x02
#define PAGE_READWRITE				0x04
#define DEF_KERNEL_BASE				0x80400000L
#define SystemModuleInformation		11
#define PROT_MEMBASE				0x80000000

typedef LONG        NTSTATUS;
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

DWORD gWinVersion;

typedef struct _STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _SYSTEM_MODULE_INFORMATION
{
        ULONG Reserved[2];
        PVOID Base;
        ULONG Size;
        ULONG Flags;
        USHORT Index;
        USHORT Unknown;
        USHORT LoadCount;
        USHORT ModuleNameOffset;
        CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION;
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
		ViewUnmap = 2
} SECTION_INHERIT;
NTSTATUS (WINAPI * _RtlAnsiStringToUnicodeString)
        (PUNICODE_STRING  DestinationString,
         IN PANSI_STRING  SourceString,
         IN BOOLEAN);

VOID (WINAPI *_RtlInitAnsiString)
        (IN OUT PANSI_STRING  DestinationString,
         IN PCHAR  SourceString);

VOID (WINAPI * _RtlFreeUnicodeString)
        (IN PUNICODE_STRING  UnicodeString);

NTSTATUS (WINAPI *_NtOpenSection)
        (OUT PHANDLE  SectionHandle,
         IN ACCESS_MASK  DesiredAccess,
         IN POBJECT_ATTRIBUTES  ObjectAttributes);

NTSTATUS (WINAPI *_NtMapViewOfSection)
        (IN HANDLE  SectionHandle,
         IN HANDLE  ProcessHandle,
         IN OUT PVOID  *BaseAddress,
         IN ULONG  ZeroBits,
         IN ULONG  CommitSize,
         IN OUT PLARGE_INTEGER  SectionOffset,        /* optional */
         IN OUT PULONG  ViewSize,
         IN SECTION_INHERIT  InheritDisposition,
         IN ULONG  AllocationType,
         IN ULONG  Protect);

NTSTATUS (WINAPI *_NtUnmapViewOfSection)
        (IN HANDLE ProcessHandle,
         IN PVOID BaseAddress);

NTSTATUS (WINAPI * _NtQuerySystemInformation)(UINT, PVOID, ULONG, PULONG);

//*******************************************************************************************************
// PE File structure declarations
//
//*******************************************************************************************************

struct PE_Header 
{
        unsigned long signature;
        unsigned short machine;
        unsigned short numSections;
        unsigned long timeDateStamp;
        unsigned long pointerToSymbolTable;
        unsigned long numOfSymbols;
        unsigned short sizeOfOptionHeader;
        unsigned short characteristics;
};

struct PE_ExtHeader
{
        unsigned short magic;
        unsigned char majorLinkerVersion;
        unsigned char minorLinkerVersion;
        unsigned long sizeOfCode;
        unsigned long sizeOfInitializedData;
        unsigned long sizeOfUninitializedData;
        unsigned long addressOfEntryPoint;
        unsigned long baseOfCode;
        unsigned long baseOfData;
        unsigned long imageBase;
        unsigned long sectionAlignment;
        unsigned long fileAlignment;
        unsigned short majorOSVersion;
        unsigned short minorOSVersion;
        unsigned short majorImageVersion;
        unsigned short minorImageVersion;
        unsigned short majorSubsystemVersion;
        unsigned short minorSubsystemVersion;
        unsigned long reserved1;
        unsigned long sizeOfImage;
        unsigned long sizeOfHeaders;
        unsigned long checksum;
        unsigned short subsystem;
        unsigned short DLLCharacteristics;
        unsigned long sizeOfStackReserve;
        unsigned long sizeOfStackCommit;
        unsigned long sizeOfHeapReserve;
        unsigned long sizeOfHeapCommit;
        unsigned long loaderFlags;
        unsigned long numberOfRVAAndSizes;
        unsigned long exportTableAddress;
        unsigned long exportTableSize;
        unsigned long importTableAddress;
        unsigned long importTableSize;
        unsigned long resourceTableAddress;
        unsigned long resourceTableSize;
        unsigned long exceptionTableAddress;
        unsigned long exceptionTableSize;
        unsigned long certFilePointer;
        unsigned long certTableSize;
        unsigned long relocationTableAddress;
        unsigned long relocationTableSize;
        unsigned long debugDataAddress;
        unsigned long debugDataSize;
        unsigned long archDataAddress;
        unsigned long archDataSize;
        unsigned long globalPtrAddress;
        unsigned long globalPtrSize;
        unsigned long TLSTableAddress;
        unsigned long TLSTableSize;
        unsigned long loadConfigTableAddress;
        unsigned long loadConfigTableSize;
        unsigned long boundImportTableAddress;
        unsigned long boundImportTableSize;
        unsigned long importAddressTableAddress;
        unsigned long importAddressTableSize;
        unsigned long delayImportDescAddress;
        unsigned long delayImportDescSize;
        unsigned long COMHeaderAddress;
        unsigned long COMHeaderSize;
        unsigned long reserved2;
        unsigned long reserved3;
};


struct SectionHeader
{
        unsigned char sectionName[8];
        unsigned long virtualSize;
        unsigned long virtualAddress;
        unsigned long sizeOfRawData;
        unsigned long pointerToRawData;
        unsigned long pointerToRelocations;
        unsigned long pointerToLineNumbers;
        unsigned short numberOfRelocations;
        unsigned short numberOfLineNumbers;
        unsigned long characteristics;
};

struct MZHeader
{
        unsigned short signature;
        unsigned short partPag;
        unsigned short pageCnt;
        unsigned short reloCnt;
        unsigned short hdrSize;
        unsigned short minMem;
        unsigned short maxMem;
        unsigned short reloSS;
        unsigned short exeSP;
        unsigned short chksum;
        unsigned short exeIP;
        unsigned short reloCS;
        unsigned short tablOff;
        unsigned short overlay;
        unsigned char reserved[32];
        unsigned long offsetToPE;
};


struct ImportDirEntry
{
        DWORD importLookupTable;
        DWORD timeDateStamp;
        DWORD fowarderChain;
        DWORD nameRVA;
        DWORD importAddressTable;
};

DWORD myStrlenA(char *ptr)
{
        DWORD len = 0;
        while(*ptr)
        {
                len++;
                ptr++;
        }

        return len;
}

BOOL myStrcmpA(char *str1, char *str2)
{
        while(*str1 && *str2)
        {
                if(*str1 == *str2)
                {
                        str1++;
                        str2++;
                }
                else
                {
                        return FALSE;
                }
        }

        if(*str1 && !*str2)
        {
                return FALSE;
        }
        else if(*str2 && !*str1)
        {
                return FALSE;
        }

        return TRUE;        
}

//*******************************************************************************************************
// Fills the various structures with info of a PE image.  The PE image is located at modulePos.
//
//*******************************************************************************************************

bool readPEInfo(char *modulePos, MZHeader *outMZ, PE_Header *outPE, PE_ExtHeader *outpeXH,
                                SectionHeader **outSecHdr)
{
        // read MZ Header
        MZHeader *mzH;
        mzH = (MZHeader *)modulePos;

        if(mzH->signature != 0x5a4d)                // MZ
        {
//                printf("File does not have MZ header\n");
                return false;
        }

        // read PE Header
        PE_Header *peH;
        peH = (PE_Header *)(modulePos + mzH->offsetToPE);

        if(peH->sizeOfOptionHeader != sizeof(PE_ExtHeader))
        {
//                printf("Unexpected option header size.\n");
                
                return false;
        }

        // read PE Ext Header
        PE_ExtHeader *peXH;
        peXH = (PE_ExtHeader *)((char *)peH + sizeof(PE_Header));

        // read the sections
        SectionHeader *secHdr = (SectionHeader *)((char *)peXH + sizeof(PE_ExtHeader));

        *outMZ = *mzH;
        *outPE = *peH;
        *outpeXH = *peXH;
        *outSecHdr = secHdr;

        return true;
}


//*******************************************************************************************************
// Returns the total size required to load a PE image into memory
//
//*******************************************************************************************************

int calcTotalImageSize(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
                                       SectionHeader *inSecHdr)
{
        int result = 0;
        int alignment = inpeXH->sectionAlignment;

        if(inpeXH->sizeOfHeaders % alignment == 0)
                result += inpeXH->sizeOfHeaders;
        else
        {
                int val = inpeXH->sizeOfHeaders / alignment;
                val++;
                result += (val * alignment);
        }
        for(int i = 0; i < inPE->numSections; i++)
        {
                if(inSecHdr[i].virtualSize)
                {
                        if(inSecHdr[i].virtualSize % alignment == 0)
                                result += inSecHdr[i].virtualSize;
                        else
                        {
                                int val = inSecHdr[i].virtualSize / alignment;
                                val++;
                                result += (val * alignment);
                        }
                }
        }

        return result;
}


//*******************************************************************************************************
// Returns the aligned size of a section
//
//*******************************************************************************************************

unsigned long getAlignedSize(unsigned long curSize, unsigned long alignment)
{        
        if(curSize % alignment == 0)
                return curSize;
        else
        {
                int val = curSize / alignment;
                val++;
                return (val * alignment);
        }
}

//*******************************************************************************************************
// Copy a PE image from exePtr to ptrLoc with proper memory alignment of all sections
//
//*******************************************************************************************************

bool loadPE(char *exePtr, MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
                        SectionHeader *inSecHdr, LPVOID ptrLoc)
{
        char *outPtr = (char *)ptrLoc;
        
        memcpy(outPtr, exePtr, inpeXH->sizeOfHeaders);
        outPtr += getAlignedSize(inpeXH->sizeOfHeaders, inpeXH->sectionAlignment);

        for(int i = 0; i < inPE->numSections; i++)
        {
                if(inSecHdr[i].sizeOfRawData > 0)
                {
                        unsigned long toRead = inSecHdr[i].sizeOfRawData;
                        if(toRead > inSecHdr[i].virtualSize)
                                toRead = inSecHdr[i].virtualSize;

                        memcpy(outPtr, exePtr + inSecHdr[i].pointerToRawData, toRead);

                        outPtr += getAlignedSize(inSecHdr[i].virtualSize, inpeXH->sectionAlignment);
                }
        }

        return true;
}


//*******************************************************************************************************
// Loads the DLL into memory and align it
//
//*******************************************************************************************************

LPVOID loadDLL(char *dllName)
{
        char moduleFilename[MAX_PATH + 1];
        LPVOID ptrLoc = NULL;
        MZHeader mzH2;
        PE_Header peH2;
        PE_ExtHeader peXH2;
        SectionHeader *secHdr2;

        GetSystemDirectory(moduleFilename, MAX_PATH);
        if((myStrlenA(moduleFilename) + myStrlenA(dllName)) >= MAX_PATH)
                return NULL;

        strcat(moduleFilename, dllName);

        // load this EXE into memory because we need its original Import Hint Table

        HANDLE fp;
        fp = CreateFile(moduleFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        
        if(fp != INVALID_HANDLE_VALUE)
        {
                BY_HANDLE_FILE_INFORMATION fileInfo;
                GetFileInformationByHandle(fp, &fileInfo);

                DWORD fileSize = fileInfo.nFileSizeLow;
//                //printf("Size = %d\n", fileSize);
                if(fileSize)
                {
                        LPVOID exePtr = HeapAlloc(GetProcessHeap(), 0, fileSize);
                        if(exePtr)
                        {
                                DWORD read;

                                if(ReadFile(fp, exePtr, fileSize, &read, NULL) && read == fileSize)
                                {                                        
                                        if(readPEInfo((char *)exePtr, &mzH2, &peH2, &peXH2, &secHdr2))
                                        {
                                                int imageSize = calcTotalImageSize(&mzH2, &peH2, &peXH2, secHdr2);                                                

                                                //ptrLoc = VirtualAlloc(NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                                                ptrLoc = HeapAlloc(GetProcessHeap(), 0, imageSize);
                                                if(ptrLoc)
                                                {                                                        
                                                        loadPE((char *)exePtr, &mzH2, &peH2, &peXH2, secHdr2, ptrLoc);
                                                }
                                        }

                                }
                                HeapFree(GetProcessHeap(), 0, exePtr);
                        }
                }
                CloseHandle(fp);
        }

        return ptrLoc;
}


DWORD procAPIExportAddr(DWORD hModule, char *apiName)
{        
        if(!hModule || !apiName)
                return 0;

        char *ptr = (char *)hModule;
        ptr += 0x3c;                // offset 0x3c contains offset to PE header
        
        ptr = (char *)(*(DWORD *)ptr) + hModule + 0x78;                // offset 78h into PE header contains addr of export table

        ptr = (char *)(*(DWORD *)ptr) + hModule;                        // ptr now points to export directory table

        // offset 24 into the export directory table == number of entries in the Export Name Pointer Table
        // table
        DWORD numEntries = *(DWORD *)(ptr + 24);
        //printf("NumEntries = %d\n", numEntries);

        DWORD *ExportNamePointerTable = (DWORD *)(*(DWORD *)(ptr + 32) + hModule);  // offset 32 into export directory contains offset to Export Name Pointer Table        
        
        DWORD ordinalBase = *((DWORD *)(ptr + 16));
        //printf("OrdinalBase is %d\n", ordinalBase);


        WORD *ExportOrdinalTable = (WORD *)((*(DWORD *)(ptr + 36)) + hModule);        // offset 36 into export directory contains offset to Ordinal Table
        DWORD *ExportAddrTable = (DWORD *)((*(DWORD *)(ptr + 28)) + hModule); // offset 28 into export directory contains offset to Export Addr Table

        for(DWORD i = 0; i < numEntries; i++)
        {                
                char *exportName = (char *)(ExportNamePointerTable[i] + hModule);

                if(myStrcmpA(exportName, apiName) == TRUE)
                {                        
                        WORD ordinal = ExportOrdinalTable[i];
                        //printf("%s (i = %d) Ordinal = %d at %X\n", exportName, i, ordinal, ExportAddrTable[ordinal]);

                        return (DWORD)(ExportAddrTable[ordinal]);
                }                
        }

        return 0;
}

//*******************************************************************************************************
// -- END PE File support functions --
//
//*******************************************************************************************************


//*********************************************************************************************
// Builds a table of native API names using the export table of ntdll.dll
//
//*********************************************************************************************

BOOL buildNativeAPITable(DWORD hModule, char *nativeAPINames[], DWORD numNames)
{
        if(!hModule)
                return FALSE;

        char *ptr = (char *)hModule;
        ptr += 0x3c;                // offset 0x3c contains offset to PE header
        
        ptr = (char *)(*(DWORD *)ptr) + hModule + 0x78;                // offset 78h into PE header contains addr of export table

        ptr = (char *)(*(DWORD *)ptr) + hModule;                        // ptr now points to export directory table

        
        // offset 24 into the export directory table == number of entries in the Name Pointer Table
        // table
        DWORD numEntries = *(DWORD *)(ptr + 24);        
        
        DWORD *ExportNamePointerTable = (DWORD *)(*(DWORD *)(ptr + 32) + hModule);  // offset 32 into export directory contains offset to Export Name Pointer Table        

        DWORD ordinalBase = *((DWORD *)(ptr + 16));

        WORD *ExportOrdinalTable = (WORD *)((*(DWORD *)(ptr + 36)) + hModule);        // offset 36 into export directory contains offset to Ordinal Table
        DWORD *ExportAddrTable = (DWORD *)((*(DWORD *)(ptr + 28)) + hModule); // offset 28 into export directory contains offset to Export Addr Table


        for(DWORD i = 0; i < numEntries; i++)
        {                
                // i now contains the index of the API in the Ordinal Table
                // ptr points to Export directory table

                WORD ordinalValue = ExportOrdinalTable[i];                
                DWORD apiAddr = (DWORD)ExportAddrTable[ordinalValue] + hModule;
                char *exportName = (char *)(ExportNamePointerTable[i] + hModule);
                
                // Win2K
                if(gWinVersion == 0 &&
                   *((unsigned char *)apiAddr) == 0xB8 && 
                   *((unsigned char *)apiAddr + 9) == 0xCD && 
                   *((unsigned char *)apiAddr + 10) == 0x2E)
                {
                        DWORD serviceNum = *(DWORD *)((char *)apiAddr + 1);
                        if(serviceNum < numNames)
                        {
                                nativeAPINames[serviceNum] = exportName;
                        }
                        //printf("%X - %s\n", serviceNum, exportName);
                }

                // WinXP
                else if(gWinVersion == 1 &&
                                *((unsigned char *)apiAddr) == 0xB8 && 
                                *((unsigned char *)apiAddr + 5) == 0xBA && 
                                *((unsigned char *)apiAddr + 6) == 0x00 &&
                                *((unsigned char *)apiAddr + 7) == 0x03 &&
                                *((unsigned char *)apiAddr + 8) == 0xFE &&
                                *((unsigned char *)apiAddr + 9) == 0x7F)
                {
                        DWORD serviceNum = *(DWORD *)((char *)apiAddr + 1);
                        if(serviceNum < numNames)
                        {
                                nativeAPINames[serviceNum] = exportName;
                        }
                        //printf("%X - %s\n", serviceNum, exportName);
                }
        }

        return TRUE;
}


//*******************************************************************************************************
// Gets address of native API's that we'll be using
//
//*******************************************************************************************************

BOOL getNativeAPIs(void)
{
        HMODULE hntdll;

        hntdll = GetModuleHandle("ntdll.dll");
                        
        *(FARPROC *)&_RtlAnsiStringToUnicodeString = 
                        GetProcAddress(hntdll, "RtlAnsiStringToUnicodeString");

        *(FARPROC *)&_RtlInitAnsiString = 
                        GetProcAddress(hntdll, "RtlInitAnsiString");

        *(FARPROC *)&_RtlFreeUnicodeString = 
                        GetProcAddress(hntdll, "RtlFreeUnicodeString");

        *(FARPROC *)&_NtOpenSection =
                        GetProcAddress(hntdll, "NtOpenSection");

        *(FARPROC *)&_NtMapViewOfSection =
                        GetProcAddress(hntdll, "NtMapViewOfSection");

        *(FARPROC *)&_NtUnmapViewOfSection =
                        GetProcAddress(hntdll, "NtUnmapViewOfSection");

        *(FARPROC *)&_NtQuerySystemInformation =
                GetProcAddress(hntdll, "ZwQuerySystemInformation");

        if(_RtlAnsiStringToUnicodeString && _RtlInitAnsiString && _RtlFreeUnicodeString &&
                _NtOpenSection && _NtMapViewOfSection && _NtUnmapViewOfSection && _NtQuerySystemInformation)
        {
                return TRUE;
        }
        return FALSE;
}


//*******************************************************************************************************
// Obtain a handle to \device\physicalmemory
//
//*******************************************************************************************************

HANDLE openPhyMem()
{
        HANDLE hPhyMem;
        OBJECT_ATTRIBUTES oAttr;

        ANSI_STRING aStr;
                
        _RtlInitAnsiString(&aStr, "\\device\\physicalmemory");
                                                
        UNICODE_STRING uStr;

        if(_RtlAnsiStringToUnicodeString(&uStr, &aStr, TRUE) != STATUS_SUCCESS)
        {                
                return INVALID_HANDLE_VALUE;        
        }

    oAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    oAttr.RootDirectory = NULL;
    oAttr.Attributes = OBJ_CASE_INSENSITIVE;
    oAttr.ObjectName = &uStr;
    oAttr.SecurityDescriptor = NULL;
    oAttr.SecurityQualityOfService = NULL;

        if(_NtOpenSection(&hPhyMem, SECTION_MAP_READ | SECTION_MAP_WRITE, &oAttr ) != STATUS_SUCCESS)
        {                
                return INVALID_HANDLE_VALUE;
        }

        return hPhyMem;
}


//*******************************************************************************************************
// Map in a section of physical memory into this process's virtual address space.
//
//*******************************************************************************************************

BOOL mapPhyMem(HANDLE hPhyMem, DWORD *phyAddr, DWORD *length, PVOID *virtualAddr)
{
        NTSTATUS                        ntStatus;
        PHYSICAL_ADDRESS        viewBase;

        *virtualAddr = 0;
        viewBase.QuadPart = (ULONGLONG) (*phyAddr);

        ntStatus = _NtMapViewOfSection(hPhyMem, (HANDLE)-1, virtualAddr, 0,
                                                                *length, &viewBase, length,
                                ViewShare, 0, PAGE_READWRITE );

        if(ntStatus != STATUS_SUCCESS)
        {
//                printf("Failed to map physical memory view of length %X at %X!", *length, *phyAddr);
                return FALSE;                                        
        }

        *phyAddr = viewBase.LowPart;
        return TRUE;
}


//*******************************************************************************************************
// Unmap section of physical memory
//
//*******************************************************************************************************

void unmapPhyMem(DWORD virtualAddr)
{
        NTSTATUS status;

        status = _NtUnmapViewOfSection((HANDLE)-1, (PVOID)virtualAddr);
        if(status != STATUS_SUCCESS)
        {
//                printf("Unmapping view failed!\n");
        }
}


//*******************************************************************************************************
// Assign SECTION_MAP_WRITE assess of \device\physicalmemory to current user.
//
//*******************************************************************************************************

BOOL assignACL(void)
{
        HANDLE hPhyMem;
        OBJECT_ATTRIBUTES oAttr;
        BOOL result = FALSE;

        ANSI_STRING aStr;
                
        _RtlInitAnsiString(&aStr, "\\device\\physicalmemory");
                                                
        UNICODE_STRING uStr;

        if(_RtlAnsiStringToUnicodeString(&uStr, &aStr, TRUE) != STATUS_SUCCESS)
        {                
                return FALSE;
        }

    oAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    oAttr.RootDirectory = NULL;
    oAttr.Attributes = OBJ_CASE_INSENSITIVE;
    oAttr.ObjectName = &uStr;
    oAttr.SecurityDescriptor = NULL;
    oAttr.SecurityQualityOfService = NULL;

        if(_NtOpenSection(&hPhyMem, READ_CONTROL | WRITE_DAC, &oAttr ) != STATUS_SUCCESS)
        {                
                return FALSE;
        }
        else
        {
                PACL dacl;
                PSECURITY_DESCRIPTOR sd;
                
                if(GetSecurityInfo(hPhyMem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
                                                &dacl, NULL, &sd) == ERROR_SUCCESS)
                {
                        EXPLICIT_ACCESS ea;
                        char userName[MAX_PATH];
                        DWORD userNameSize = MAX_PATH-1;

                        GetUserName(userName, &userNameSize);
                        ea.grfAccessPermissions = SECTION_MAP_WRITE;
                        ea.grfAccessMode = GRANT_ACCESS;
                        ea.grfInheritance = NO_INHERITANCE;
                        ea.Trustee.pMultipleTrustee = NULL;
                        ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
                        ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
                        ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
                        ea.Trustee.ptstrName = userName;

                        PACL newDacl;
                        if(SetEntriesInAcl(1, &ea, dacl, &newDacl) == ERROR_SUCCESS)
                        {
                                if(SetSecurityInfo(hPhyMem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
                                                                newDacl, NULL) == ERROR_SUCCESS)
                                {                
                                        result = TRUE;
                                }

                                LocalFree(newDacl);
                        }
                }
        }

        return result;        
}


//*******************************************************************************************************
// Gets the kernel base address
//
//*******************************************************************************************************

DWORD getKernelBase(void)
{
        HANDLE hHeap = GetProcessHeap();
        
        NTSTATUS Status;
    ULONG cbBuffer = 0x8000;
    PVOID pBuffer = NULL;
        DWORD retVal = DEF_KERNEL_BASE;

    do
    {
                pBuffer = HeapAlloc(hHeap, 0, cbBuffer);
                if (pBuffer == NULL)
                        return DEF_KERNEL_BASE;

                Status = _NtQuerySystemInformation(SystemModuleInformation,
                                        pBuffer, cbBuffer, NULL);

                if(Status == STATUS_INFO_LENGTH_MISMATCH)
                {
                        HeapFree(hHeap, 0, pBuffer);
                        cbBuffer *= 2;
                }
                else if(Status != STATUS_SUCCESS)
                {
                        HeapFree(hHeap, 0, pBuffer);
                        return DEF_KERNEL_BASE;
                }
    }
    while (Status == STATUS_INFO_LENGTH_MISMATCH);

        DWORD numEntries = *((DWORD *)pBuffer);
        SYSTEM_MODULE_INFORMATION *smi = (SYSTEM_MODULE_INFORMATION *)((char *)pBuffer + sizeof(DWORD));

        for(DWORD i = 0; i < numEntries; i++)
        {
                if(strcmpi(smi->ImageName, "ntoskrnl.exe"))
                {
                        //printf("%.8X - %s\n", smi->Base, smi->ImageName);
                        retVal = (DWORD)(smi->Base);
                        break;
                }
                smi++;
        }

        HeapFree(hHeap, 0, pBuffer);

        return retVal;
}

#endif // !defined(AFX_COMMON_H__26B16518_B067_46E6_9E85_7DBF1D1DBB5D__INCLUDED_)
