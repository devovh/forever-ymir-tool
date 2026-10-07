// Starting, watching and stopping Ymir, and what it needs (README of Ymir): Npcap in WinPcap compatibility mode, the capture adapter
// in interface.cfg, the Ymir made for the client's build, sniffs in dumps\ next to it. Ymir stops by itself a few seconds after the
// game closes; Stop sends it Ctrl+C like closing its console window, it is never killed (the sniff could be cut).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;

namespace YmirTool
{
    public sealed class Recording
    {
        public string Path;
        public int Build;
        public DateTime Started, Modified;
        public long Size;
    }

    public static class YmirRunner
    {
        public static string NpcapProblem()
        {
            string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (!Directory.Exists(System.IO.Path.Combine(sys, "Npcap")) && !File.Exists(System.IO.Path.Combine(sys, "wpcap.dll")))
                return "Npcap is not installed (https://npcap.com, tick \"WinPcap API-compatible mode\")";
            if (!File.Exists(System.IO.Path.Combine(sys, "wpcap.dll")))
                return "Npcap is installed without \"WinPcap API-compatible mode\": install it again with that option";
            return null;
        }

        public static string Adapter(string folder)
        {
            try
            {
                string text = File.ReadAllText(System.IO.Path.Combine(folder, "interface.cfg")).Trim();
                int end = text.IndexOf('}');
                return end > 0 ? text.Substring(0, end + 1) : (text.Length > 0 ? text : null);
            }
            catch { return null; }
        }

        // the Ymir for this build: regedit.exe is the original for 70124, regedit_<build>.exe the copies made by this tool
        public static string YmirFor(string folder, int build)
        {
            string path = System.IO.Path.Combine(folder, build == YmirPatcher.OriginalBuild ? "regedit.exe" : "regedit_" + build + ".exe");
            if (!File.Exists(path)) return null;
            try
            {
                // the WowB.exe version check inside it must be this build
                var spot = YmirPatcher.Spots[2];
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    var b = new byte[4];
                    fs.Position = spot.FileOffset + spot.ValueAt;
                    fs.Read(b, 0, 4);
                    return BitConverter.ToInt32(b, 0) == build ? path : null;
                }
            }
            catch { return null; }
        }

        public static List<Process> Running(string folder)
        {
            var list = new List<Process>();
            string full = System.IO.Path.GetFullPath(folder).TrimEnd('\\') + "\\";
            foreach (var p in Process.GetProcesses())
            {
                if (!p.ProcessName.StartsWith("regedit", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    if (p.MainModule.FileName.StartsWith(full, StringComparison.OrdinalIgnoreCase)) list.Add(p);
                }
                catch { }       // the real Windows regedit (elevated) cannot be read: not ours
            }
            return list;
        }

        public static Process Start(string ymir)
        {
            return Process.Start(new ProcessStartInfo(ymir) { WorkingDirectory = System.IO.Path.GetDirectoryName(ymir), UseShellExecute = true });
        }

        [DllImport("kernel32.dll", SetLastError = true)] static extern bool AttachConsole(uint pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool FreeConsole();
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GenerateConsoleCtrlEvent(uint ctrlEvent, uint group);

        // Ctrl+C into Ymir's console; true if it ended within the time
        public static bool Stop(Process p, int waitMs)
        {
            FreeConsole();
            if (!AttachConsole((uint)p.Id)) return false;
            SetConsoleCtrlHandler(IntPtr.Zero, true);          // the Ctrl+C must not end this tool
            GenerateConsoleCtrlEvent(0, 0);
            Thread.Sleep(300);
            FreeConsole();
            SetConsoleCtrlHandler(IntPtr.Zero, false);
            return p.WaitForExit(waitMs);
        }

        public static List<Recording> Recordings(string folder)
        {
            var list = new List<Recording>();
            string dumps = System.IO.Path.Combine(folder, "dumps");
            if (!Directory.Exists(dumps)) return list;
            foreach (var path in Directory.GetFiles(dumps, "*.pkt"))
            {
                var fi = new FileInfo(path);
                var r = new Recording { Path = path, Size = fi.Length, Modified = fi.LastWriteTime };
                int build; DateTime started;
                if (PktFile.PeekHeader(path, out build, out started)) { r.Build = build; r.Started = started; }
                else r.Started = fi.CreationTime;
                list.Add(r);
            }
            return list.OrderByDescending(r => r.Modified).ToList();
        }

        // the game's Cache folder (Ymir README: delete it before sniffing so the client asks the server for everything again)
        public static string CacheFolder(string wowExe)
        {
            return string.IsNullOrEmpty(wowExe) ? null : System.IO.Path.Combine(System.IO.Path.GetDirectoryName(wowExe), "Cache");
        }

        public static string FormatSize(long bytes)
        {
            return bytes >= 1 << 20 ? (bytes / 1048576.0).ToString("0.0") + " MB" : (bytes / 1024.0).ToString("0") + " KB";
        }
    }
}
