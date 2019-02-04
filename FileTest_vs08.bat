@echo off
rem Build file for VS 2008. Expects MS Visual Studio to be installed
rem in %ProgramFiles%\Microsoft Visual Studio 9.0

rem determine where the program files are, both for 64-bit and 32-bit Windows
set PROGRAM_FILES_DIR=%ProgramFiles%
if "x%ProgramFiles(x86)%" == "x" goto CONFIGURE_VS_VARS32
set PROGRAM_FILES_DIR=%ProgramFiles(x86)%

:CONFIGURE_VS_VARS32
call "%PROGRAM_FILES_DIR%\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x86
devenv.com FileTest_vs08.sln /Rebuild "Release|Win32" /project "FileTest"

:CONFIGURE_VS_VARS64
call "%PROGRAM_FILES_DIR%\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" x64
devenv.com FileTest_vs08.sln /Rebuild "Release|x64" /project "FileTest"
