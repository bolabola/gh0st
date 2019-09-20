#if !defined(AFX_PUBLIC_H__CADW455A_)
#define AFX_PUBLIC_H__CADW455A_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define XorValue 10			//杀进程PID的异或加密值
#define IDR_ENCODE 513		//资源中的上线信息
#define IDR_CONFIG 514		//资源中的服务信息
#define IOCTL_KILL  (ULONG)CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA )
typedef struct _MYDATA
{
	ULONG Pid;
	ULONG ModuleAddress;
}MYDATA;//杀进程时候的结构体






#endif