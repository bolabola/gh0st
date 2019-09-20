// Gh0stServer.h : main header file for the GH0STSERVER application
//

#if !defined(AFX_GH0STSERVER_H__38CF4905_97D4_4261_A6E9_69197B962AF2__INCLUDED_)
#define AFX_GH0STSERVER_H__38CF4905_97D4_4261_A6E9_69197B962AF2__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CGh0stServerApp:
// See Gh0stServer.cpp for the implementation of this class
//

class CGh0stServerApp : public CWinApp
{
public:
	CGh0stServerApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CGh0stServerApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CGh0stServerApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_GH0STSERVER_H__38CF4905_97D4_4261_A6E9_69197B962AF2__INCLUDED_)
