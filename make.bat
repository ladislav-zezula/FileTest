@echo off
if not "x%WDKDIR%" == "x" goto SELECT_BINARY
echo The WDKDIR environment variable is not set
echo Set this variable to your WDK directory (without ending backslash)
echo Example: set WDKDIR C:\WinDDK\6001
pause
goto:eof

:SELECT_BINARY
set PROJECT_DIR=%~dp0
set SAVE_PATH=%PATH%
set BINARY_NAME=FileTest
set LANGUAGE=En
set BUILD_TYPE=fre

:BUILD_BINARY_64
echo Building %BINARY_NAME%.exe (64-bit) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ %BUILD_TYPE% x64 wnet
cd /d %PROJECT_DIR%
build.exe -czgw
del build%BUILD_TYPE%_wnet_amd64.log
echo.

:BUILD_BINARY_32
echo Building %BINARY_NAME%.exe (32-bit) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ %BUILD_TYPE% w2k
cd /d %PROJECT_DIR%
build.exe -czgw
del build%BUILD_TYPE%_w2k_x86.log
echo.

:POST_BUILD_STEPS
PostBuild.exe .\obj%BUILD_TYPE%_wnet_amd64\amd64\%BINARY_NAME%.exe /tools /subsystem4
PostBuild.exe .\obj%BUILD_TYPE%_w2k_x86\i386\%BINARY_NAME%.exe /tools /subsystem4

:CLEANUP
if exist %BINARY_NAME%_WDK.rc del %BINARY_NAME%_WDK.rc
if exist build.bat del build.bat
set PATH=%SAVE_PATH%
