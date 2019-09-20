// EnDeCode.h: interface for the EnDeCode class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_ENDECODE_H__F9AC5B27_9A18_4FFE_A59D_2005C556ABD2__INCLUDED_)
#define AFX_ENDECODE_H__F9AC5B27_9A18_4FFE_A59D_2005C556ABD2__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

static char base642[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

class EnDeCode  
{
public:
	EnDeCode();
	virtual ~EnDeCode();
public:
	static int base64_encode2(const void *data, int size, char **str);
	static char* Encode(char *str);
	static int base64_decode2(const char *str, char **data);
	static char* Decode(char *str);
	static char* encrypt(char* str);
	static char* decrypt(char* str);
};

#endif // !defined(AFX_ENDECODE_H__F9AC5B27_9A18_4FFE_A59D_2005C556ABD2__INCLUDED_)
