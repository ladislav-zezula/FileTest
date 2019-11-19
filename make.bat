@echo off
if not "x%WDKDIR%" == "x" goto SELECT_EXE
echo The WDKDIR environment variable is not set
echo Set this variable to your WDK directory (without ending backslash)
echo Example: set WDKDIR C:\WinDDK\6001
pause
goto:eof

:SELECT_EXE
set PROJECT_DIR=%~dp0
set EXE_NAME=FileTest

:BUILD_EXE_32
echo Building %EXE_NAME%.exe 32-bit (free) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre w2k
cd %PROJECT_DIR%
set USER_LIB_PATH=..\aaa\lib32
build.exe -czgw
echo.

:COPY_EXE_32
PostBuild.exe .\objfre_w2k_x86\i386\%EXE_NAME%.exe /tools /subsystem4
del buildfre_w2k_x86.log
echo.

:BUILD_EXE_64
echo Building %EXE_NAME%.exe 64-bit (free) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre x64 wlh
cd %PROJECT_DIR%
set USER_LIB_PATH=..\aaa\lib64
build.exe -czgw
echo.

:COPY_EXE_64
PostBuild.exe .\objfre_wlh_amd64\amd64\%EXE_NAME%.exe %EXE_NAME%.rc /tools /subsystem4
del buildfre_wlh_amd64.log
echo.

rem Clean temporary files ...
rem if exist objfre_wxp_x86 rd /s /q objfre_wxp_x86
if exist build.bat del build.bat
