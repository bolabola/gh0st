///////////////////////////////////////////////////////////////////   
  //   File:                 NetClose.H   
  //   Version:           1.01   
    
  #define   NETBUFF_SIZE         0x208   
    
  #define   NetSessionEnum_PROFILE     (   DWORD   (__stdcall   *)                   (   LPSTR,   DWORD,   LPBYTE,   DWORD,   LPDWORD,   LPDWORD   )   )   
  #define   NetSessionDel_PROFILE       (   DWORD   (__stdcall   *)                                                                   (   LPSTR,   LPSTR,   DWORD   )   )   
  ///////////////////////////////////////////////////////////////////   
  //   File:                 NetClose.CPP   
  //   Version:           1.01   
  ///////////////////////////////////////////////////////////////////   
  //   Define:                             BOOL   NetCloseAll(   VOID   )   
  //   Parameters:                     None   
  //   Return:                             TRUE   or   FALSE   
  //   
  //   Author:                             Mr.Huang   fei   
  //   Time:                                 5/7/1998   
  //   Note:                                 Can   only   be   used   on   Windows95   &   Windows98   
  //   Remark:                             Close   all   network   connections   
  ///////////////////////////////////////////////////////////////////   
  BOOL   NetCloseAll(   VOID   )   
  {   
                  BYTE         byBuff[NETBUFF_SIZE];   
                  DWORD       dwNetRet                                 =   0;;   
                  DWORD       i                                               =   0;   
                  DWORD       dwEntries                               =   0;   
                  DWORD       dwTotalEntries                     =   0;   
                  LPSTR       szClient                                 =   NULL;   
                  DWORD       dwUserName                             =   0;   
                  BOOL         bRet                                         =   FALSE;   
                  LPBYTE     lpbyBuff   =   (LPBYTE)byBuff;   
    
                  DWORD   (__stdcall   *   hookNetSessionEnum)(   LPSTR,   DWORD,                                                                   LPBYTE,   DWORD,   LPDWORD,   LPDWORD   );   
                  DWORD   (__stdcall   *   hookNetSessionDel)(   LPSTR,   LPSTR,   DWORD   );   
    
                  HINSTANCE   hMod   =   LoadLibrary(   "SVRAPI.DLL"   );   
                  if(   hMod   !=   NULL   )   
                  {   
                                  //   Get   the   address   of   function   
                                  hookNetSessionEnum   =   NetSessionEnum_PROFILE   
                                                                            GetProcAddress   
                                                                    (   hMod,   TEXT("NetSessionEnum")   );   
                                  hookNetSessionDel     =   NetSessionDel_PROFILE   
                                                                            GetProcAddress   
                                                                    (   hMod,   TEXT("NetSessionDel")   );   
    
                                  if(   (   hookNetSessionDel   !=   NULL   )   &&   
                                          (   hookNetSessionEnum   !=   NULL   )   )   
                                  {   
                                                  dwNetRet   =   hookNetSessionEnum(     NULL,   
                                                                                        0x32,   byBuff,   
                                                                                        NETBUFF_SIZE,   &dwEntries,   
                                                                                        &dwTotalEntries   );   
                                                  if(   dwNetRet   ==   0   )   
                                                  {   
                                                          bRet   =   TRUE;   
                                                          for(   i=0;   i   <   dwTotalEntries;   i++   )   
                                                          {   
                                                              szClient   =   (LPSTR)(((DWORD   *)   
                                                                                            lpbyBuff)[0]);   
                                                              dwUserName   =   ((DWORD   *)lpbyBuff)[2];   
                                                              dwNetRet   =   hookNetSessionDel(   NULL,   
                                                                                          szClient,   dwUserName   );   
                                                              if(   dwNetRet   !=   0   )   
                                                              {   
                                                                              bRet   =   FALSE;   
                                                                              break;   
                                                              }   
                                                              lpbyBuff   +=   26;   
                                                          }   
                                                  }   //   NetSessionEnum(...)   
                                                  else   
                                                                  bRet   =   FALSE;   
                                  }   //   GetProcAddress(...)   
                                  else   
                                                  bRet   =   FALSE;   
    
                                  FreeLibrary(   hMod   );   
                  }   //   LoadLibrary(...)   
                  return   bRet;   
  }