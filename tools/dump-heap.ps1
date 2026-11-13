param(
    [string]$out = "",
    [int]$procId = 0
)
# Zrzut pamieci SPOZA obrazu modulu: chodzi o sterty, na ktore wskazuja sloty .data.
# dump-image.ps1 czyta tylko obraz Wow.exe (0..SizeOfImage) i dlatego nie zawiera obiektu sesji.

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class HeapMem {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool i, int p);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr h, IntPtr a, byte[] b, IntPtr n, out IntPtr r);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] public static extern void GetSystemInfo(out SYSTEM_INFO si);
    [DllImport("kernel32.dll")] public static extern int VirtualQueryEx(IntPtr h, IntPtr a, out MEMORY_BASIC_INFORMATION m, IntPtr l);

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_INFO { public ushort wProcessorArchitecture, wReserved; public uint dwPageSize; public IntPtr lpMinimumApplicationAddress, lpMaximumApplicationAddress; public IntPtr dwActiveProcessorMask; public uint dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity; public ushort wProcessorLevel, wProcessorRevision; }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect, __alignment1; public IntPtr RegionSize; public uint State, Protect, Type, __alignment2; }

    public static List<string> Regions(IntPtr h, long from, long to) {
        var list = new List<string>();
        SYSTEM_INFO si; GetSystemInfo(out si);
        long step = si.dwPageSize;
        long a = from;
        while (a < to) {
            MEMORY_BASIC_INFORMATION m;
            if (VirtualQueryEx(h, (IntPtr)a, out m, (IntPtr)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) break;
            long rs = m.RegionSize.ToInt64();
            if (rs <= 0) break;
            // tylko pamiec zatwierdzona, czytelna, nie obraz modulu i nie guard
            bool ok = m.State == 0x1000 && (m.Protect & 0x100) == 0
                      && (m.Protect == 0x04 || m.Protect == 0x02 || m.Protect == 0x20 || m.Protect == 0x40);
            if (ok) list.Add(a.ToString() + " " + rs.ToString());
            a += rs;
        }
        return list;
    }
}
"@

if ($out -eq "") { $out = Join-Path $PSScriptRoot "wow70938_heap.img" }

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

$h = [HeapMem]::OpenProcess(0x0410, $false, $p.Id)
if ($h -eq [IntPtr]::Zero) { Write-Host "OpenProcess nieudane - uruchom jako administrator."; exit 1 }

# interesuje nas 64 MB nad obrazem modulu i tyle samo pod nim
$sizeOfImage = 0x7422000
$from = $base - 0x4000000
$to = $base + $sizeOfImage + 0x4000000

$regions = [HeapMem]::Regions($h, $from, $to)
Write-Host ("czytelnych regionow: {0}" -f $regions.Count)

# mapa: adres -> dane, w pliku jedno po drugim; osobny indeks
$idx = New-Object System.Collections.Generic.List[string]
$fs = New-Object System.IO.FileStream($out, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
$bufSize = 1048576
$pos = 0
$ok = 0
foreach ($r in $regions) {
    $parts = $r.Split(" ")
    $addr = [int64]$parts[0]
    $len = [int64]$parts[1]
    if ($len -gt 67108864) { continue }
    $chunk = New-Object byte[] $len
    $got = [IntPtr]::Zero
    if ([HeapMem]::ReadProcessMemory($h, [IntPtr]$addr, $chunk, [IntPtr]$len, [ref]$got)) {
        $fs.Write($chunk, 0, $len)
        $idx.Add(("0x{0:x} {1} {2}" -f $addr, $len, $pos))
        $pos += $len
        $ok++
    }
}
$fs.Close()
[HeapMem]::CloseHandle($h)

$idxPath = $out + ".idx"
[System.IO.File]::WriteAllLines($idxPath, $idx)

Write-Host ("zapisano: {0} ({1:0.0} MB)" -f (Get-Item $out).FullName, ((Get-Item $out).Length / 1MB))
Write-Host ("indeks : {0} ({1} regionow)" -f $idxPath, $ok)
