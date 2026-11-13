param(
    [string]$out = "",
    [int]$procId = 0
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DumpMem {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool i, int p);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr n, out IntPtr r);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
"@

if ($out -eq "") { $out = Join-Path $PSScriptRoot "wow70938.img" }

if ($procId -eq 0) {
    $p = Get-Process -Name Wow, WowB -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $p) { Write-Host "Klient Wow.exe / WowB.exe nie dziala."; exit 1 }
} else {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p) { Write-Host "Brak procesu PID $procId."; exit 1 }
}

$base = $p.MainModule.BaseAddress.ToInt64()
Write-Host ("proces: PID {0} ({1})" -f $p.Id, $p.ProcessName)
Write-Host ("baza  : 0x{0:x}" -f $base)

$h = [DumpMem]::OpenProcess(0x0410, $false, $p.Id)
if ($h -eq [IntPtr]::Zero) { Write-Host "OpenProcess nieudane - uruchom jako administrator."; exit 1 }

# naglowek PE: rozmiar obrazu i sekcje
$hdr = New-Object byte[] 4096
$got = [IntPtr]::Zero
if (-not [DumpMem]::ReadProcessMemory($h, [IntPtr]$base, $hdr, [IntPtr]4096, [ref]$got)) {
    Write-Host "Nie moge odczytac naglowka PE."; exit 1
}
$pe = [BitConverter]::ToInt32($hdr, 0x3C)
$sizeOfImage = [BitConverter]::ToUInt32($hdr, $pe + 24 + 56)
$nsec = [BitConverter]::ToUInt16($hdr, $pe + 6)
$optsz = [BitConverter]::ToUInt16($hdr, $pe + 20)
$secStart = $pe + 24 + $optsz
Write-Host ("obraz: 0x{0:x} bajtow ({1:0.0} MB), sekcji: {2}" -f $sizeOfImage, ($sizeOfImage / 1MB), $nsec)

# plik o rozmiarze obrazu, z PE w naglowku ale z prawdziwa baza procesu
$fs = New-Object System.IO.FileStream($out, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
$fs.SetLength([int64]$sizeOfImage)
$buf = New-Object byte[] 4194304
$readable = 0; $blocked = 0

for ($off = 0; $off -lt $sizeOfImage; $off += $buf.Length) {
    $n = [int]([Math]::Min([int64]$buf.Length, $sizeOfImage - $off))
    $chunk = New-Object byte[] $n
    $ok = [DumpMem]::ReadProcessMemory($h, [IntPtr]($base + $off), $chunk, [IntPtr]$n, [ref]$got)
    if ($ok) {
        $fs.Position = $off
        $fs.Write($chunk, 0, $n)
        $readable++
    } else {
        $blocked++
    }
    if ((($off / $buf.Length) % 8) -eq 0) {
        Write-Host ("  {0:0.0} MB..." -f ($off / 1MB))
    }
}

# naglowek PE: plik ma RVA == offset, wiec wpisujemy go od razu (baza procesu + rozmiar obrazu)
$fs.Position = 0
$fs.Write($hdr, 0, 4096)
$fs.Position = $pe + 24 + 24
$fs.Write([BitConverter]::GetBytes([int64]$base), 0, 8)
$fs.Flush()
$fs.Close()
[DumpMem]::CloseHandle($h)

$fi = Get-Item $out
Write-Host ""
Write-Host ("zapisano: {0}" -f $fi.FullName)
Write-Host ("rozmiar : {0:0.0} MB" -f ($fi.Length / 1MB))
Write-Host ("czytelne bloki: {0}, zablokowane: {1}" -f $readable, $blocked)
if ($blocked -gt 0) { Write-Host "(zablokowane obszary sa w pliku zerami - to normalne, sa nieuzywane)" }
