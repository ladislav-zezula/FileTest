:: Build file for Visual Studio 2008 and 2017
@echo off

:: Save the values of INCLUDE, LIB and PATH
set SAVE_INCLUDE=%INCLUDE%
set SAVE_LIB=%LIB%
set SAVE_PATH=%PATH%
set PROJECT_NAME=FileTest

:: Determine where the program files are, both for 64-bit and 32-bit Windows
if exist "%ProgramFiles%"      set PROGRAM_FILES_DIR=%ProgramFiles%
if exist "%ProgramFiles(x86)%" set PROGRAM_FILES_DIR=%ProgramFiles(x86)%

:: Determine the installed version of Visual Studio (Prioritize Enterprise over Professional)
if exist "%PROGRAM_FILES_DIR%\Microsoft Visual Studio 9.0\VC\vcvarsall.bat"                               set VCVARS_2008=%PROGRAM_FILES_DIR%\Microsoft Visual Studio 9.0\VC\vcvarsall.bat
if exist "%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvarsall.bat" set VCVARS_2017=%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvarsall.bat
if exist "%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"   set VCVARS_2017=%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build\vcvarsall.bat
if exist "%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" set VCVARS_2019=%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat
if exist "%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat"   set VCVARS_2019=%PROGRAM_FILES_DIR%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat

::Build the project using Visual Studio 2008 and 2017
rem call :BuildProject "%VCVARS_2008%" x86 %PROJECT_NAME%_vs08.sln
rem call :BuildProject "%VCVARS_2008%" x64 %PROJECT_NAME%_vs08.sln
call :BuildProject "%VCVARS_2019%" x86 %PROJECT_NAME%_vs17.sln
call :BuildProject "%VCVARS_2019%" x64 %PROJECT_NAME%_vs17.sln
goto:eof

::-----------------------------------------------------------------------------
:: Build the project
::
:: Parameters:
::
::   %1     Full path to the VCVARS.BAT file
::   %2     Target build platform (x86 or x64)
::   %3     Plain name of the .sln solution file
::

:BuildProject
call %1 %2
if "%2" == "x86" set SLN_TRG=Win32
if "%2" == "x64" set SLN_TRG=x64
devenv.com %3 /project "%PROJECT_NAME%" /rebuild "Release|%SLN_TRG%"

:: Restore environment variables to the old level
set INCLUDE=%SAVE_INCLUDE%
set LIB=%SAVE_LIB%
set PATH=%SAVE_PATH%
set VSINSTALLDIR=
set VCINSTALLDIR=
set DevEnvDir=
goto:eof
