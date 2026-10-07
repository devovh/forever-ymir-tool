@echo off
rem Builds dist\YmirTool.exe with the C# compiler that ships with Windows (.NET Framework 4.8), like the Forever launcher.
setlocal
cd /d "%~dp0"
set "FW=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319"
if not exist "%FW%\csc.exe" ( echo Cannot find %FW%\csc.exe & exit /b 1 )
if not exist dist mkdir dist
"%FW%\csc.exe" /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 /out:dist\YmirTool.exe ^
  /resource:data\opcodes.txt,YmirTool.opcodes.txt /resource:data\fingerprints.txt,YmirTool.fingerprints.txt ^
  /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Core.dll ^
  src\*.cs
if errorlevel 1 exit /b 1
echo OK: dist\YmirTool.exe
