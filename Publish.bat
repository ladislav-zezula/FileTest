@echo off
rem This BAT file updates the ZIP file that is to be uploaded to www.zezula.net
rem Only use when both 32-bit and 64-bit are properly compiled

cd .\bin

:FILETEST_32BIT
if not exist .\Win32\Release\FileTest.exe goto FILETEST_64BIT
echo Publishing FileTest (32-bit) ...
copy .\Win32\Release\FileTest.exe .\Win32\FileTest.exe 
rem PostBuild.exe .\Win32\FileTest.exe /subsystem4 /tools
if exist \\files-eu.srv.int.avast.com\pub_users\zezula\Tools32 copy .\Win32\FileTest.exe \\files-eu.srv.int.avast.com\pub_users\zezula\Tools32\FileTest.exe
zip.exe -u9 ..\..\..\WWW\web\download\filetest.zip .\Win32\FileTest.exe
echo.

:FILETEST_64BIT
if not exist .\x64\Release\FileTest.exe goto ADD_HISTORY
echo Publishing FileTest (64-bit) ...
copy .\x64\Release\FileTest.exe .\x64\FileTest.exe 
rem PostBuild.exe .\x64\FileTest.exe /subsystem4 /tools
if exist \\files-eu.srv.int.avast.com\pub_users\zezula\Tools64 copy .\x64\FileTest.exe \\files-eu.srv.int.avast.com\pub_users\zezula\Tools64\FileTest.exe
zip.exe -u9 ..\..\..\WWW\web\download\filetest.zip .\x64\FileTest.exe
echo.

:ADD_HISTORY
echo Adding text files ...
copy ..\doc\History.txt History.txt
copy ..\doc\ReadMe.txt  ReadMe.txt
zip.exe -u9 ..\..\..\WWW\web\download\filetest.zip History.txt
zip.exe -u9 ..\..\..\WWW\web\download\filetest.zip Readme.txt
echo.

cd ..
PostBuild.exe FileTest.rc
echo Press any key to exit ...
pause >nul
