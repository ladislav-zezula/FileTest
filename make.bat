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

:BUILD_EXE_64
echo Building %EXE_NAME%.exe (64-bit) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre x64 wlh
cd %PROJECT_DIR%
set USER_LIB_PATH=..\aaa\lib64
build.exe -czgw
del buildfre_wlh_amd64.log
echo.

:BUILD_EXE_32
echo Building %EXE_NAME%.exe (32-bit) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre wxp
cd %PROJECT_DIR%
set USER_LIB_PATH=..\aaa\lib32
build.exe -czgw
del buildfre_wxp_x86.log
echo.

:COPY_EXE
PostBuild.exe .\objfre_wlh_amd64\amd64\%EXE_NAME%.exe %EXE_NAME%.rc /subsystem4 /tools
PostBuild.exe .\objfre_wxp_x86\i386\%EXE_NAME%.exe /subsystem4 /tools

:CLEANUP
if exist build.bat del build.bat
