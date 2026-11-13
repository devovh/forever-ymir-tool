# Buduje YmirTool.exe. Wymaga csc.exe z .NET Framework 4 (jest w kazdym Windows 10/11).
Set-Location (Split-Path $PSScriptRoot -Parent)
$FW = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319"
& "$FW\csc.exe" /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 `
    /out:dist\YmirTool.exe `
    /resource:data\opcodes.txt,YmirTool.opcodes.txt `
    /resource:data\fingerprints.txt,YmirTool.fingerprints.txt `
    /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Core.dll `
    src\*.cs sniffer\Crypto.cs
Write-Host "exit=$LASTEXITCODE"
