#if !defined(AFX_SETTINGSVIEW_H__0BE25EB6_DFFA_4CEB_A4E7_BD98236BB73A__INCLUDED_)
#define AFX_SETTINGSVIEW_H__0BE25EB6_DFFA_4CEB_A4E7_BD98236BB73A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// SettingsView.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CSettingsView form view

#ifndef __AFXEXT_H__
#include <afxext.h>
#endif

#include "control/HoverEdit.h"
#include "control/WinXPButtonST.h"
//#define CButton	CCJFlatButton

LPCTSTR FindConfigString(char *strFileName, LPCTSTR lpString);

class CSettingsView : public CFormView
{
protected:
	DECLARE_DYNCREATE(CSettingsView)

// Form Data
public:
	//{{AFX_DATA(CSettingsView)
	enum { IDD = IDD_SETTINGS };
	CString	m_remote_host;
	CString	m_remote_port;
	UINT	m_listen_port;
	UINT	m_max_connections;
	BOOL	m_connect_auto;
	BOOL	m_bIsDisablePopTips;
	BOOL	m_bIsSaveAsDefault;
	CString	m_encode;
	CString	m_ServiceDisplayName;
	CString	m_ServiceDescription;
	CStringA	m_pass;
	CString	m_username;
	CString	m_userpass;
    CString m_pathName;
    CString m_strServiceConfig;
	BOOL	m_delete;
	//}}AFX_DATA

// Attributes
public:

// Operations
public:

	CSettingsView();           // public constructor used by dynamic creation
	virtual ~CSettingsView();
// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CSettingsView)
	public:
        void PromptMessageBox(const CString& msg);
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView);
	//}}AFX_VIRTUAL

// Implementation
protected:

#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

	// Generated message map functions
	//{{AFX_MSG(CSettingsView)
	afx_msg void OnChangeConfig(UINT id);
	afx_msg void OnResetport();
	afx_msg void OnConnectAuto();
	afx_msg void OnCheckAuth();
	afx_msg void OnTestProxy();
	afx_msg void OnCheckProxy();
	afx_msg void OnTestMaster();
	afx_msg void OnDisablePoptips();
	afx_msg void OnSaveasDefault();
	afx_msg void OnShengCheng();
	afx_msg void OnChangePass();
    afx_msg LRESULT OnPromptMessageBox(WPARAM wParam, LPARAM lParam);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
private:
	static	DWORD WINAPI	TestProxy(LPVOID lparam);
	static	DWORD WINAPI	TestMaster(LPVOID lparam);
    static unsigned WINAPI ConnectToServerProc(LPVOID lParam);
	void UpdateProxyControl();
	bool m_bFirstShow;
	CHoverEdit	m_Edit[9];
	CWinXPButtonST	m_Btn[3];
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_SETTINGSVIEW_H__0BE25EB6_DFFA_4CEB_A4E7_BD98236BB73A__INCLUDED_)
