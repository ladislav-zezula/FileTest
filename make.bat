@echo off
if not "x%WDKDIR%" == "x" goto SELECT_EXE
echo The WDKDIR environment variable is not set
echo Set this variable to your WDK directory (without ending backslash)
echo Example: set WDKDIR C:\WinDDK\6001
pause
goto:eof

:SELECT_EXE
set PROJECT_DIR=%~dp0
set SAVE_PATH=%PATH%
set EXE_NAME=FileTest
set LANGUAGE=En

:BUILD_EXE_64
echo Building %EXE_NAME%.exe (64-bit) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre x64 wlh
cd %PROJECT_DIR%
build.exe -czgw
del buildfre_wlh_amd64.log
echo.

:BUILD_EXE_32
echo Building %EXE_NAME%.exe (32-bit) ...
set DDKBUILDENV=
call %WDKDIR%\bin\setenv.bat %WDKDIR%\ fre w2k
cd %PROJECT_DIR%
build.exe -czgw
del buildfre_w2k_x86.log
echo.

:COPY_FILES
PostBuild.exe .\objfre_wlh_amd64\amd64\%EXE_NAME%.exe /tools /subsystem4
PostBuild.exe .\objfre_w2k_x86\i386\%EXE_NAME%.exe /tools /subsystem4

:CLEANUP
if exist %EXE_NAME%_WDK.rc del %EXE_NAME%_WDK.rc
if exist build.bat del build.bat
set PATH=%SAVE_PATH%
