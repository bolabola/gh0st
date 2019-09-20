// RESSDT.cpp : Defines the entry point for the console application.
//

#include "R3.h"

int ReSSDTR3()
{
        MZHeader mzH2;
        PE_Header peH2;
        PE_ExtHeader peXH2;
        SectionHeader *secHdr2;

//        printf("SDTrestore Version 0.1 Proof-of-Concept by SIG^2 G-TEC (www.security.org.sg)\n\n");

        OSVERSIONINFO ov;
        ov.dwOSVersionInfoSize = sizeof(ov);
        GetVersionEx(&ov);
        if(ov.dwMajorVersion != 5)
        {
//                printf("Sorry, this version supports only Win2K and WinXP.\n");
                return 1;
        }

        if(ov.dwMinorVersion != 0 && ov.dwMinorVersion != 1)
        {
//                printf("Sorry, this version supports only Win2K and WinXP.\n");
                return 1;
        }
        gWinVersion = ov.dwMinorVersion;

        if(!getNativeAPIs())
        {
//                printf("Failed to get addresses of Native APIs!\n");
                return 1;
        }

        assignACL();
        HANDLE hPhyMem = openPhyMem();
        if(hPhyMem == INVALID_HANDLE_VALUE)
                assignACL();

        hPhyMem = openPhyMem();
        if(hPhyMem == INVALID_HANDLE_VALUE)
        {
//                        printf("Could not open physical memory device!\nMake sure you are running as Administrator.\n");
                        return 1;
        }

        PVOID exeAddr = loadDLL("\\ntoskrnl.exe");
        if(!exeAddr)
        {
//                printf("Failed to load ntoskrnl.exe!\n");
                return 1;
        }

        DWORD sdtAddr = procAPIExportAddr((DWORD)exeAddr, "KeServiceDescriptorTable");
        if(!sdtAddr)
        {
//                printf("Failed to get address of KeServiceDescriptorTable!\n");
                return 1;
        }
        
        if(!readPEInfo((char *)exeAddr, &mzH2, &peH2, &peXH2, &secHdr2))
        {
//                printf("Failed to get PE header of ntoskrnl.exe!\n");
                return 1;
        }

        DWORD kernelPhyBase = getKernelBase() - PROT_MEMBASE;
        DWORD kernelOffset = kernelPhyBase - peXH2.imageBase;

//        printf("KeServiceDescriptorTable\t\t%X\n", sdtAddr + kernelPhyBase + PROT_MEMBASE);

        unsigned char *ptr = NULL;
        DWORD pAddr = sdtAddr + kernelPhyBase;
        DWORD wantedAddr = pAddr;
        DWORD len = 0x2000;

        // map in page containing KeServiceDecriptorTable
        if(mapPhyMem(hPhyMem, &pAddr, &len, (LPVOID *)&ptr))
        {
                DWORD start = wantedAddr - pAddr;
                DWORD serviceTableAddr, sdtCount; 
                DWORD wantedBytes = len - start;
                if(wantedBytes >= 4)
                {
                        serviceTableAddr = *((DWORD *)(&ptr[start]));
//                        printf("KeServiceDecriptorTable.ServiceTable\t%X\n", serviceTableAddr);
                        if(wantedBytes >= 12)
                        {
                                sdtCount = *(((DWORD *)(&ptr[start])) + 2);
//                                printf("KeServiceDescriptorTable.ServiceLimit\t%d\n", sdtCount);
                        }
                }
                else
                {
//                        printf("Sorry, an unexpected situation occurred!\n");
                        return 1;
                }

                unmapPhyMem((DWORD)ptr);
//                printf("\n");

                if(sdtCount >= 300)
                {
//                        printf("Sorry, an unexpected error occurred! SDT Count > 300???\n");
                        return 1;
                }

                pAddr = serviceTableAddr - PROT_MEMBASE;
                wantedAddr = pAddr;
                ptr = NULL;
                len = 0x2000;
                if(mapPhyMem(hPhyMem, &pAddr, &len, (LPVOID *)&ptr))
                {
                        start = wantedAddr - pAddr;
                        DWORD numEntries = (len - start) >> 2;
                        if(numEntries >= sdtCount)
                        {
                                char **nativeApiNames = NULL;
                                nativeApiNames = (char **)malloc(sizeof(char *) * sdtCount);
                                if(!nativeApiNames)
                                {
//                                        printf("Failed to allocate memory for Native API name table.\n");
                                        return 1;
                                }
                                memset(nativeApiNames, 0, sizeof(char *) * sdtCount);

                                PVOID ntdll = loadDLL("\\ntdll.dll");
                                if(!ntdll)
                                {
//                                        printf("Failed to load ntdll.dll!\n");
                                        return 1;
                                }

                                buildNativeAPITable((DWORD)ntdll, nativeApiNames, sdtCount);

                                DWORD *serviceTable = (DWORD *)(&ptr[start]);
                                DWORD *fileServiceTable = (DWORD *)((DWORD)exeAddr + wantedAddr - kernelOffset - peXH2.imageBase);

                                if(!IsBadReadPtr(fileServiceTable, sizeof(DWORD)) && 
                                   !IsBadReadPtr(&fileServiceTable[sdtCount-1], sizeof(DWORD)))
                                {
                                        DWORD hookCount = 0;
                                        for(DWORD i = 0; i < sdtCount; i++)
                                        {                                                        
                                                if((serviceTable[i] - PROT_MEMBASE - kernelOffset) != fileServiceTable[i])
                                                {
//                                                        printf("%-25s %3X --[hooked by unknown at %X]--\n", 
//                                                                  (nativeApiNames[i] ? nativeApiNames[i] : "Unknown API"), 
//                                                                  i, serviceTable[i]);
                                                        hookCount++;
                                                }
                                                
                                        }
//                                        printf("\nNumber of Service Table entries hooked = %u\n", hookCount);
                                        
                                        if(hookCount)
                                        {
                                                        for(DWORD i = 0; i < sdtCount; i++)
                                                        {
                                                                if((serviceTable[i] - PROT_MEMBASE - kernelOffset) != fileServiceTable[i])
                                                                {
                                                                        serviceTable[i] = fileServiceTable[i] + PROT_MEMBASE + kernelOffset;
//                                                                        printf("[+] Patched SDT entry %.2X to %.8X\n", i, 
//                                                                                fileServiceTable[i] + PROT_MEMBASE + kernelOffset);
                                                                }
                                                        }
                                         }
                                }
                                else
                                {
//                                        printf("It's likely that the SDT service table has been relocated.\n"
//                                                   "This POC code cannot support patching of relocated SDT service table.\n");
                                }

                        }
                        unmapPhyMem((DWORD)ptr);
                }
        }

        return 0;
}
