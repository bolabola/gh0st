// Dialupass.cpp: implementation of the CDialupass class.
//
//////////////////////////////////////////////////////////////////////
#include "Dialupass.h"
#include "until.h"
#include <tchar.h>
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CDialupass::CDialupass()
{
    m_nMax = 0;
    m_lpCurrentUser = GetCurrentLoginUser();
    m_nRasCount = GetRasEntryCount();
    m_PassWords = new PASSWORDS[m_nRasCount];
    OneInfo = new COneInfo*[m_nRasCount];
    m_nUsed = 0;
    m_nCount = 0;
    GetRasEntries();
}

CDialupass::~CDialupass()
{
    for (int i = 0; i < m_nRasCount; i++)
        delete OneInfo[i];
    delete m_PassWords;
    if (!m_lpCurrentUser)
        delete m_lpCurrentUser;
}

DWORD CDialupass::GetRasEntryCount()
{
    int		nCount = 0;
    TCHAR	*lpPhoneBook[2];
    TCHAR	szPhoneBook1[MAX_PATH + 1], szPhoneBook2[MAX_PATH + 1];
    GetWindowsDirectory(szPhoneBook1, ARRAYSIZE(szPhoneBook1));
    lstrcpy(_tcschr(szPhoneBook1, TEXT('\\')) + 1, TEXT("Documents and Settings\\"));
    lstrcat(szPhoneBook1, m_lpCurrentUser);
    lstrcat(szPhoneBook1, TEXT("\\Application Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk"));
    SHGetSpecialFolderPath(NULL, szPhoneBook2, 0x23, 0);
    wsprintf(szPhoneBook2, TEXT("%s\\%s"), szPhoneBook2, TEXT("Microsoft\\Network\\Connections\\pbk\\rasphone.pbk"));

    lpPhoneBook[0] = szPhoneBook1;
    lpPhoneBook[1] = szPhoneBook2;

    DWORD	nSize = 1024 * 4;
    TCHAR	*lpszReturnBuffer = new TCHAR[nSize];

    for (int i = 0; i < sizeof(lpPhoneBook) / sizeof(int); i++)
    {
        memset(lpszReturnBuffer, 0, nSize);
        GetPrivateProfileSectionNames(lpszReturnBuffer, nSize, lpPhoneBook[i]);
        for (TCHAR *lpSection = lpszReturnBuffer; *lpSection != TEXT('\0'); lpSection += lstrlen(lpSection) + 1)
        {
            nCount++;
        }
    }
    delete lpszReturnBuffer;
    return nCount;
}

LPTSTR CDialupass::GetLocalSid()
{
    union
    {
        SID s;
        char c[256];
    }Sid;
    DWORD sizeSid = sizeof(Sid);
    TCHAR DomainName[256];
    DWORD sizeDomainName = sizeof(DomainName);
    SID_NAME_USE peUse;
    LPTSTR pSid;

    if (m_lpCurrentUser == NULL)
        return NULL;

    if (!LookupAccountName(NULL, m_lpCurrentUser, (SID*)&Sid, &sizeSid, DomainName, &sizeDomainName, &peUse))
        return NULL;
    if (!IsValidSid(&Sid))
        return NULL;


    typedef BOOL(WINAPI *ConvertSid2StringSid)(PSID, LPTSTR *);
    ConvertSid2StringSid proc;
    HINSTANCE	hLibrary = LoadLibrary(TEXT("advapi32.dll"));
    proc = (ConvertSid2StringSid)GetProcAddress(hLibrary, "ConvertSidToStringSid");
    if (proc)   
        proc((SID*)&Sid.s, &pSid);
    FreeLibrary(hLibrary);
    return pSid;
}


void CDialupass::AnsiStringToLsaStr(LPSTR AValue, PLSA_UNICODE_STRING lsa)
{
    lsa->Length = lstrlenA(AValue) * 2;
    lsa->MaximumLength = lsa->Length + 2;
    lsa->Buffer = (PWSTR)malloc(lsa->MaximumLength);
    MultiByteToWideChar(NULL, NULL, (LPCSTR)AValue, lstrlenA(AValue), lsa->Buffer, lsa->MaximumLength);
}


PLSA_UNICODE_STRING CDialupass::GetLsaData(LPSTR KeyName)
{
    LSA_OBJECT_ATTRIBUTES LsaObjectAttribs;
    LSA_HANDLE LsaHandle;
    LSA_UNICODE_STRING LsaKeyName;
    NTSTATUS nts;
    PLSA_UNICODE_STRING OutData;

    ZeroMemory(&LsaObjectAttribs, sizeof(LsaObjectAttribs));
    nts = LsaOpenPolicy(NULL, &LsaObjectAttribs, POLICY_GET_PRIVATE_INFORMATION, &LsaHandle);
    if (nts != 0)return NULL;
    AnsiStringToLsaStr(KeyName, &LsaKeyName);
    nts = LsaRetrievePrivateData(LsaHandle, &LsaKeyName, &OutData);
    if (nts != 0)return NULL;
    nts = LsaClose(LsaHandle);
    if (nts != 0)return NULL;
    return OutData;
}
/////////
void CDialupass::ParseLsaBuffer(LPCWSTR Buffer, USHORT Length)
{
    char AnsiPsw[1024];
    TCHAR chr, PswStr[256];
    PswStr[0] = 0;
    WideCharToMultiByte(0, NULL, Buffer, Length, AnsiPsw, 1024, 0, 0);

    for (int i = 0, SpacePos = 0, TXT = 0; i < Length / 2 - 2; i++)
    {
        chr = AnsiPsw[i];
        if (chr == 0)
        {
            SpacePos++;
            switch (SpacePos)
            {
            case 1:
                PswStr[TXT] = chr;
                _tcscpy(m_PassWords[m_nUsed].UID, PswStr);
                break;
            case 6:
                PswStr[TXT] = chr;
                _tcscpy(m_PassWords[m_nUsed].login, PswStr);
                break;
            case 7:
                PswStr[TXT] = chr;
                _tcscpy(m_PassWords[m_nUsed].pass, PswStr);
                m_PassWords[m_nUsed].used = false;
                m_nUsed++;
                break;
            }
            ZeroMemory(PswStr, 256);
            TXT = 0;
        }
        else
        {
            PswStr[TXT] = chr;
            TXT++;
        }
        if (SpacePos == 9)SpacePos = 0;
    }
}
///////////
void CDialupass::GetLsaPasswords()
{
    PLSA_UNICODE_STRING PrivateData;
    char Win2k[] = "RasDialParams!%s#0";
    char WinXP[] = "L$_RasDefaultCredentials#0";
    char temp[256];

    wsprintfA(temp, Win2k, GetLocalSid());

    PrivateData = GetLsaData(temp);
    if (PrivateData != NULL)
    {
        ParseLsaBuffer(PrivateData->Buffer, PrivateData->Length);
        LsaFreeMemory(PrivateData->Buffer);
    }

    PrivateData = GetLsaData(WinXP);
    if (PrivateData != NULL)
    {
        ParseLsaBuffer(PrivateData->Buffer, PrivateData->Length);
        LsaFreeMemory(PrivateData->Buffer);
    }
}


bool CDialupass::GetRasEntries()
{

    int		nCount = 0;
    TCHAR	*lpPhoneBook[2];
    TCHAR	szPhoneBook1[MAX_PATH + 1], szPhoneBook2[MAX_PATH + 1];
    GetWindowsDirectory(szPhoneBook1, ARRAYSIZE(szPhoneBook1));
    lstrcpy(_tcschr(szPhoneBook1, TEXT('\\')) + 1, TEXT("Documents and Settings\\"));
    lstrcat(szPhoneBook1, m_lpCurrentUser);
    lstrcat(szPhoneBook1, TEXT("\\Application Data\\Microsoft\\Network\\Connections\\pbk\\rasphone.pbk"));
    SHGetSpecialFolderPath(NULL, szPhoneBook2, 0x23, 0);
    wsprintf(szPhoneBook2, TEXT("%s\\%s"), szPhoneBook2, TEXT("Microsoft\\Network\\Connections\\pbk\\rasphone.pbk"));

    lpPhoneBook[0] = szPhoneBook1;
    lpPhoneBook[1] = szPhoneBook2;


    OSVERSIONINFO osi;
    osi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osi);

    if (osi.dwPlatformId == VER_PLATFORM_WIN32_NT && osi.dwMajorVersion >= 5)
    {
        GetLsaPasswords();
    }

    DWORD	nSize = 1024 * 4;
    TCHAR	*lpszReturnBuffer = new TCHAR[nSize];

    for (int i = 0; i < sizeof(lpPhoneBook) / sizeof(int); i++)
    {
        memset(lpszReturnBuffer, 0, nSize);
        GetPrivateProfileSectionNames(lpszReturnBuffer, nSize, lpPhoneBook[i]);
        for (TCHAR *lpSection = lpszReturnBuffer; *lpSection != TEXT('\0'); lpSection += lstrlen(lpSection) + 1)
        {
            //by zhangyl
            //char	*lpRealSection = (char *)UTF8ToGB2312(lpSection);
            TCHAR	*lpRealSection = lpSection;
            TCHAR	strDialParamsUID[256];
            TCHAR	strUserName[256];
            TCHAR	strPassWord[256];
            TCHAR	strPhoneNumber[256];
            TCHAR	strDevice[256];
            memset(strDialParamsUID, 0, sizeof(strDialParamsUID));
            memset(strUserName, 0, sizeof(strUserName));
            memset(strPassWord, 0, sizeof(strPassWord));
            memset(strPhoneNumber, 0, sizeof(strPhoneNumber));
            memset(strDevice, 0, sizeof(strDevice));


            int	nBufferLen = GetPrivateProfileString(lpSection, TEXT("DialParamsUID"), 0,
                strDialParamsUID, ARRAYSIZE(strDialParamsUID), lpPhoneBook[i]);

            if (nBufferLen > 0)//DialParamsUID=4326020    198064
            {
                for (int j = 0; j < (int)m_nRasCount; j++)
                {
                    if (lstrcmp(strDialParamsUID, m_PassWords[j].UID) == 0)
                    {
                        lstrcpy(strUserName, m_PassWords[j].login);
                        lstrcpy(strPassWord, m_PassWords[j].pass);
                        m_PassWords[j].used = true;
                        m_nUsed++;
                        break;
                    }
                }
            }

            GetPrivateProfileString(lpSection, TEXT("PhoneNumber"), 0,
                strPhoneNumber, ARRAYSIZE(strDialParamsUID), lpPhoneBook[i]);
            GetPrivateProfileString(lpSection, TEXT("Device"), 0,
                strDevice, ARRAYSIZE(strDialParamsUID), lpPhoneBook[i]);
            //char *lpRealDevice = (char *)UTF8ToGB2312(strDevice);
            //char *lpRealUserName = (char *)UTF8ToGB2312(strUserName);
            //Set(strDialParamsUID, lpRealSection, lpRealUserName, strPassWord, strPhoneNumber, lpRealDevice);
            Set(strDialParamsUID, lpRealSection, strUserName, strPassWord, strPhoneNumber, strDevice);
            delete	lpRealSection;
            //delete	lpRealUserName;
            //delete	lpRealDevice;
        }
    }
    delete lpszReturnBuffer;

    return true;
}

BOOL CDialupass::Set(TCHAR *DialParamsUID, TCHAR *Name, TCHAR *User, TCHAR *Password, TCHAR *PhoneNumber, TCHAR *Device)
{
    for (int i = 0; i < m_nMax; i++){
        if (0 == _tcscmp(OneInfo[i]->Get(STR_DialParamsUID), DialParamsUID)){

            if (Name != NULL)
                OneInfo[i]->Set(STR_Name, Name);
            if (User != NULL)
                OneInfo[i]->Set(STR_User, User);
            if (Password != NULL)
                OneInfo[i]->Set(STR_Password, Password);
            if (PhoneNumber != NULL)
                OneInfo[i]->Set(STR_PhoneNumber, PhoneNumber);
            if (Device != NULL)
                OneInfo[i]->Set(STR_Device, Device);
            return TRUE;
        }
    }

    if (m_nMax < m_nRasCount){

        OneInfo[m_nMax] = new COneInfo;
        OneInfo[m_nMax]->Set(STR_DialParamsUID, DialParamsUID);
        OneInfo[m_nMax]->Set(STR_Name, Name);
        OneInfo[m_nMax]->Set(STR_User, User);
        OneInfo[m_nMax]->Set(STR_Password, Password);
        OneInfo[m_nMax]->Set(STR_PhoneNumber, PhoneNumber);
        OneInfo[m_nMax]->Set(STR_Device, Device);
        m_nMax++;
        return TRUE;
    }
    return false;
}

LPCSTR CDialupass::UTF8ToGB2312(char UTF8Str[])
{
    if (UTF8Str == NULL || lstrlenA(UTF8Str) == 0)
        return "";
    int	nStrLen = lstrlenA(UTF8Str) * 2;
    char *lpWideCharStr = new char[nStrLen];
    char *lpMultiByteStr = new char[nStrLen];

    MultiByteToWideChar(CP_UTF8, 0, UTF8Str, -1, (LPWSTR)lpWideCharStr, nStrLen);
    WideCharToMultiByte(CP_ACP, 0, (LPWSTR)lpWideCharStr, -1, lpMultiByteStr, nStrLen, 0, 0);

    delete lpWideCharStr;
    return lpMultiByteStr;
}
