@echo off
rem Builds dist\ForeverSniffer.exe with the C# compiler that ships with Windows (.NET Framework 4.8), like YmirTool.exe.
setlocal
cd /d "%~dp0"
set "FW=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319"
if not exist "%FW%\csc.exe" ( echo Cannot find %FW%\csc.exe & exit /b 1 )
if not exist dist mkdir dist
"%FW%\csc.exe" /nologo /target:exe /platform:x64 /optimize+ /codepage:65001 /out:dist\ForeverSniffer.exe ^
  /r:System.Core.dll ^
  sniffer\*.cs
if errorlevel 1 exit /b 1
echo OK: dist\ForeverSniffer.exe
