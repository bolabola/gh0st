#if !defined(AFX_GENGXIN_H__65E2A9AA_B38B_4B9B_8C30_A9172399BDC6__INCLUDED_)
#define AFX_GENGXIN_H__65E2A9AA_B38B_4B9B_8C30_A9172399BDC6__INCLUDED_

#include "resource.h"

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// GENGXIN.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CGENGXIN dialog

class CGENGXIN : public CDialog
{
// Construction
public:
	CGENGXIN(CWnd* pParent = NULL);   // standard constructor

// Dialog Data
	//{{AFX_DATA(CGENGXIN)
	enum { IDD = IDD_GENGXIN };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CGENGXIN)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CGENGXIN)
	afx_msg void OnButton1();
	virtual BOOL OnInitDialog();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_GENGXIN_H__65E2A9AA_B38B_4B9B_8C30_A9172399BDC6__INCLUDED_)
