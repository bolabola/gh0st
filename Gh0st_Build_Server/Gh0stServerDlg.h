// Gh0stServerDlg.h : header file
//

#if !defined(AFX_GH0STSERVERDLG_H__08EB067A_1E59_4BA4_A05E_4122201CBA83__INCLUDED_)
#define AFX_GH0STSERVERDLG_H__08EB067A_1E59_4BA4_A05E_4122201CBA83__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CGh0stServerDlg dialog

class CGh0stServerDlg : public CDialog
{
// Construction
public:
	CGh0stServerDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CGh0stServerDlg)
	enum { IDD = IDD_GH0STSERVER_DIALOG };
	int		m_port;
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CGh0stServerDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CGh0stServerDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnStart();
	afx_msg void OnExit();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_GH0STSERVERDLG_H__08EB067A_1E59_4BA4_A05E_4122201CBA83__INCLUDED_)
