// Common.h: interface for the Common class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_COMMON_H__5687820B_CA9B_4F38_AB9F_5D087E95F0FD__INCLUDED_)
#define AFX_COMMON_H__5687820B_CA9B_4F38_AB9F_5D087E95F0FD__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
/*
#include <iphlpapi.h>
#pragma comment (lib, "iphlpapi.lib")
#include <winsock2.h>
#pragma comment (lib, "ws2_32.lib")
*/
#include <Tlhelp32.h>

class Common  
{
public:
	Common();
	virtual ~Common();
public:
	static HINSTANCE g_hInstance;
	static BOOL g_exit;
	static DWORD GetProcessID(LPCTSTR lpProcessName);
	static void StartService(LPCTSTR lpService);
	static BOOL StopService(LPCTSTR lpService);
//	static BOOL Stop360( char *IPADDR );
};

#endif // !defined(AFX_COMMON_H__5687820B_CA9B_4F38_AB9F_5D087E95F0FD__INCLUDED_)
