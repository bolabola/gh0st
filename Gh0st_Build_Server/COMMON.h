// COMMON.h: interface for the COMMON class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_COMMON_H__C64953B4_0BDE_4413_BF48_B03069296E42__INCLUDED_)
#define AFX_COMMON_H__C64953B4_0BDE_4413_BF48_B03069296E42__INCLUDED_

#include "WINSOCK.H"

#define Request_DOWN			0x9
#define File_Buffer				0x10
#define File_Buffer_Finish		0x11

typedef struct
{
	BYTE	Flags;
	DWORD	Buffer_Size;
	BYTE	Buffer[1024];
}NET_DATA, *LPNET_DATA;

char *DAT_NAME = "Server.dat";
char *INI_NAME = "Config.ini";
char DAT_PATH[MAX_PATH] = {0}, INI_PATH[MAX_PATH] = {0};

SOCKET g_hSocket;
HANDLE g_hLinstenThread = NULL;

#endif // !defined(AFX_COMMON_H__C64953B4_0BDE_4413_BF48_B03069296E42__INCLUDED_)
