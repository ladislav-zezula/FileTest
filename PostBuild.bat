@echo off
rem Batch file for post-build processing
rem
rem Parameters:
rem PostBuild %1 %2
rem
rem   %1 - Platform name (Win32 or x64)
rem   %2 - Configuration name (Debug or Release)
rem
rem

if "x%2" == "xDebug" goto exit
if "x%1" == "xx64" goto exit

PostBuild.exe .\bin\%1\%2\FileTest.exe FileTest.rc

:exit
