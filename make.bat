@echo off
if not "x%WDKDIR%" == "x" goto SELECT_EXE
echo The WDKDIR environment variable is not set
echo Set this variable to your WDK directory (without ending backslash)
echo Example: set WDKDIR C:\WinDDK\5308
pause
goto exit

:SELECT_EXE
set EXE_NAME=FileTest
E:

:BUILD_EXE_32
echo Building %EXE_NAME%.exe 32-bit (free) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre
cd \Ladik\Appdir\FileTest
set LIB=%LIB%;..\aaa\lib32
build.exe -czgw
echo.

:COPY_EXE_32
rem if not exist .\objfre_wlh_x86\i386\%EXE_NAME%.dll goto exit
rem md ..\bin >nul
rem md ..\bin\Win32 >nul
rem copy .\objfre_wlh_x86\i386\%EXE_NAME%.dll ..\FileSpy_exe\Res\%EXE_NAME%32.dll >nul
rem copy buildfre_wlh_x86.log .\objfre_wlh_x86 >nul
del buildfre_wlh_x86.log
echo.

:BUILD_EXE_64
rem echo Building %EXE_NAME%.exe 64-bit (free) ...
rem set DDKBUILDENV=
rem call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre x64
rem cd \Ladik\Appdir\FileTest
rem build.exe -czgw
echo.

:COPY_EXE_64
rem if not exist .\objfre_wlh_amd64\amd64\%EXE_NAME%.dll goto exit
rem md ..\bin >nul
rem md ..\bin\x64 >nul
rem copy .\objfre_wlh_amd64\amd64\%EXE_NAME%.dll ..\FileSpy_exe\Res\%EXE_NAME%64.dll >nul
rem copy buildfre_wlh_amd64.log .\objfre_wlh_amd64 >nul
del buildfre_wlh_amd64.log
echo.

rem Increment build number ...
rem mkbuildnum %EXE_NAME%.rc

rem Clean temporary files ...
if exist build.bat del build.bat

:exit
