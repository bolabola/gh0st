#if !defined(AFX_GUANYU_H__0BD988DE_26F8_4943_A0E3_00B5B323197A__INCLUDED_)
#define AFX_GUANYU_H__0BD988DE_26F8_4943_A0E3_00B5B323197A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// GUANYU.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// GUANYU form view

#ifndef __AFXEXT_H__
#include <afxext.h>
#endif

class GUANYU : public CFormView
{
public:
	GUANYU();           // protected constructor used by dynamic creation
	DECLARE_DYNCREATE(GUANYU)

// Form Data
public:
	//{{AFX_DATA(GUANYU)
	enum { IDD = IDD_GUANYU };
		// NOTE: the ClassWizard will add data members here
	//}}AFX_DATA

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(GUANYU)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual void OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView);
	//}}AFX_VIRTUAL

// Implementation
protected:
	virtual ~GUANYU();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

	// Generated message map functions
	//{{AFX_MSG(GUANYU)
		// NOTE - the ClassWizard will add and remove member functions here.
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_GUANYU_H__0BD988DE_26F8_4943_A0E3_00B5B323197A__INCLUDED_)
