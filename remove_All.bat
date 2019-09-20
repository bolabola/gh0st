@echo off

echo ----------------------------------------------------
echo Press any key to delete all files with ending:
echo  *.aps *.idb *.ncp *.obj *.pch *.tmp *.sbr
echo Visual c++/.Net junk 
echo ----------------------------------------------------
echo witch
echo ----------------------------------------------------


pause

echo ----------------------------------------------------
echo ---开始删除文件
echo ----------------------------------------------------
del /F /Q /S *.aps *.idb *.ncp *.obj *.pch *.sbr *.tmp *.pdb *.bsc *.ilk *.res *.ncb *.opt *.suo *.dep *.exp Thumbs.db *.sdf BuildLog.htm *.user *.bak 



echo ----------------------------------------------------
echo ---开始删除文件夹
echo ----------------------------------------------------
rd /q /S   ipch


echo 以下为删除文件夹，慎用
echo  for /r . %%a in (.) do @if exist "%%a\.svn" rd /s /q "%%a\.svn"
echo  Rem for /r . %%a in (.) do @if exist "%%a\.svn" @echo "%%a\.svn"

pause


