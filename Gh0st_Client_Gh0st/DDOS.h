#if !defined(AFX_DDOS_H__C3D5A998_EE50_4822_B184_C791BB141ECE__INCLUDED_)
#define AFX_DDOS_H__C3D5A998_EE50_4822_B184_C791BB141ECE__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// DDOS.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CDDOS form view

#ifndef __AFXEXT_H__
#include <afxext.h>
#endif

class CDDOS : public CFormView
{
public:
	CDDOS();           // protected constructor used by dynamic creation
	BYTE DDOS_Flag;
	void SendSelectCommand(PBYTE pData, UINT nSize);
	BOOL MyInitialization( DDOS_DATA *data );
	DECLARE_DYNCREATE(CDDOS)

// Form Data
public:
	//{{AFX_DATA(CDDOS)
	enum { IDD = IDD_DDOS };
	CString	m_url;
	CString	m_cookie;
	DWORD	m_attacktime;
	DWORD	m_cc1;
	DWORD	m_cc2;
	DWORD	m_fabao;
	DWORD	m_port;
	DWORD	m_sleep;
	DWORD	m_thread;
	CString	m_getpage;
	//}}AFX_DATA

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CDDOS)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView);
	//}}AFX_VIRTUAL

// Implementation
protected:
	virtual ~CDDOS();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

	// Generated message map functions
	//{{AFX_MSG(CDDOS)
	afx_msg void OnUDPFlood();
	afx_msg void OnDdosBegin();
	afx_msg void OnDdosStop();
	afx_msg void OnTcpflood();
	afx_msg void OnUdpflood();
	afx_msg void OnCc();
	afx_msg void OnHttpget();
	afx_msg void OnICMP();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_DDOS_H__C3D5A998_EE50_4822_B184_C791BB141ECE__INCLUDED_)
