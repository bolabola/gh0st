// Loader.cpp : 定义控制台应用程序的入口点。
//  用来加载Server.dll

#include "stdafx.h"
#include "Loader.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 唯一的应用程序对象

CWinApp theApp;

using namespace std;

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	HMODULE hdll = LoadLibrary(_T("Server.dll"));
	if (!hdll)
	{
		return 0;
	}
	typedef void (*STARTSERVER)();
	STARTSERVER p_StartServer;
	p_StartServer = (STARTSERVER)GetProcAddress(hdll,"StartServer");
	p_StartServer();
	return 0;
}
