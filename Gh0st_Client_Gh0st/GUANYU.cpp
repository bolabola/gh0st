// GUANYU.cpp : implementation file
//

#include "stdafx.h"
#include "gh0st.h"
#include "GUANYU.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BOOL First_view = TRUE;
/////////////////////////////////////////////////////////////////////////////
// GUANYU

IMPLEMENT_DYNCREATE(GUANYU, CFormView)

GUANYU::GUANYU()
	: CFormView(GUANYU::IDD)
{
	//{{AFX_DATA_INIT(GUANYU)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
}

GUANYU::~GUANYU()
{
}

void GUANYU::DoDataExchange(CDataExchange* pDX)
{
	CFormView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(GUANYU)
		// NOTE: the ClassWizard will add DDX and DDV calls here
	//}}AFX_DATA_MAP
}


BEGIN_MESSAGE_MAP(GUANYU, CFormView)
	//{{AFX_MSG_MAP(GUANYU)
		// NOTE - the ClassWizard will add and remove mapping macros here.
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// GUANYU diagnostics

#ifdef _DEBUG
void GUANYU::AssertValid() const
{
	CFormView::AssertValid();
}

void GUANYU::Dump(CDumpContext& dc) const
{
	CFormView::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// GUANYU message handlers

void GUANYU::OnActivateView(BOOL bActivate, CView* pActivateView, CView* pDeactiveView) 
{
	// TODO: Add your specialized code here and/or call the base class
	if (First_view)
	{
        CString str = _T("");
		//GetDlgItem(IDC_GUANYU)->SetWindowText(str);
		First_view = FALSE;
	}

	CFormView::OnActivateView(bActivate, pActivateView, pDeactiveView);
}
