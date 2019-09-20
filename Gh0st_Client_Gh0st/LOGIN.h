#if !defined(AFX_LOGIN_H__3286D204_C760_48C5_ACC0_5C1D67E505AA__INCLUDED_)
#define AFX_LOGIN_H__3286D204_C760_48C5_ACC0_5C1D67E505AA__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// LOGIN.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// LOGIN dialog

class LOGIN : public CDialog
{
// Construction
public:
	LOGIN(CWnd* pParent = NULL);   // standard constructor
	DWORD dLogin;
	CIniFile m_inifile;
// Dialog Data
	//{{AFX_DATA(LOGIN)
	enum { IDD = IDD_LOGIN };
	CString	m_username;
	CString	m_userpass;
	BOOL	m_baocun;
	CString	m_onlinepass;
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(LOGIN)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(LOGIN)
	afx_msg void OnExit();
	afx_msg void OnLogin();
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_LOGIN_H__3286D204_C760_48C5_ACC0_5C1D67E505AA__INCLUDED_)
