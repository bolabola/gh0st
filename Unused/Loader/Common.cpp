// Common.cpp: implementation of the Common class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "Common.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
HINSTANCE Common::g_hInstance = NULL;
BOOL Common::g_exit = FALSE;

Common::Common()
{

}

Common::~Common()
{

}

DWORD Common::GetProcessID(LPCTSTR lpProcessName)
{
	DWORD RetProcessID = 0;
	HANDLE handle=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32* info=new PROCESSENTRY32;
	info->dwSize=sizeof(PROCESSENTRY32);
	
	if(Process32First(handle,info))
	{
		if (strcmpi(info->szExeFile,lpProcessName) == 0)
		{
			RetProcessID = info->th32ProcessID;
			return RetProcessID;
		}
		while(Process32Next(handle,info) != FALSE)
		{
			if (lstrcmpi(info->szExeFile,lpProcessName) == 0)
			{
				RetProcessID = info->th32ProcessID;
				return RetProcessID;
			}
		}
	}
	return RetProcessID;
}

void Common::StartService(LPCTSTR lpService)
{
	SC_HANDLE hSCManager = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS );
	if ( NULL != hSCManager )
	{
		SC_HANDLE hService = OpenService(hSCManager, lpService, SERVICE_ALL_ACCESS );
		if ( NULL != hService )
		{
			ChangeServiceConfig( hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			::StartService(hService, 0, NULL);
			CloseServiceHandle( hService );
		}
		CloseServiceHandle( hSCManager );
	}
}

BOOL Common::StopService(LPCTSTR lpService)
{
	SC_HANDLE        schSCManager;
	SC_HANDLE        schService;
	SERVICE_STATUS   RemoveServiceStatus;
	
	schSCManager=::OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);//打开服务控制管理器数据库
	if (schSCManager!=NULL)
	{
		schService=::OpenService(schSCManager,lpService,SERVICE_ALL_ACCESS);//获得服务对象的句柄
		if (schService!=NULL)
		{
			if(QueryServiceStatus(schService,&RemoveServiceStatus)!=0)
			{
				if(RemoveServiceStatus.dwCurrentState!=SERVICE_STOPPED)//停止服务
				{
					if(ControlService(schService,SERVICE_CONTROL_STOP,&RemoveServiceStatus)!=0)
					{
						while(RemoveServiceStatus.dwCurrentState==SERVICE_STOP_PENDING)         
						{
							Sleep(10);
							QueryServiceStatus(schService,&RemoveServiceStatus);
						}
					}
				}
			}    
			CloseServiceHandle(schService);
		}	
		::CloseServiceHandle(schSCManager);
	}
	else 
		return FALSE;
	
	return TRUE;
}
/*
BOOL Common::Stop360( char *IPADDR )
{
	DWORD dwRet=0;   
	PIP_INTERFACE_INFO plfTable=NULL;
	IP_ADAPTER_INDEX_MAP AdaptMap;
	DWORD dwBufferSize=0;
	TCHAR szFriendName[256]={0};
	DWORD tchSize=sizeof(TCHAR)*256;
	
	ULONG NTEContext   =   0;
	ULONG NTEInstance=0;
	IPAddr NewIP;
	IPAddr NewMask;
	dwRet=GetInterfaceInfo(NULL,&dwBufferSize);   
	if(dwRet==ERROR_INSUFFICIENT_BUFFER)   
	{
		plfTable=(PIP_INTERFACE_INFO)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwBufferSize);
		GetInterfaceInfo(plfTable,&dwBufferSize);
	}
	AdaptMap=plfTable->Adapter[0];//i是第几块网卡
	NewIP   =   inet_addr( IPADDR );
	NewMask   =   inet_addr("255.255.255.0");
	dwRet = AddIPAddress( NewIP, NewMask, AdaptMap.Index, &NTEContext, &NTEInstance );
	HeapFree(GetProcessHeap(),HEAP_ZERO_MEMORY,plfTable);
	if( NO_ERROR == dwRet )
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}

}
*/