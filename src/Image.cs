// Access to a WowB.exe image: the running client (read-only) or a dump file of it (for the self-test).
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace YmirTool
{
    public sealed class Section
    {
        public string Name;
        public long Rva, Size;
    }

    public abstract class GameImage
    {
        public long Base;               // where the image is loaded (a dump keeps the runtime base in its PE header)
        public long Size;
        public List<Section> Sections = new List<Section>();

        public abstract byte[] Read(long rva, int count);   // unreadable bytes come back as 0

        protected void ParseHeaders(byte[] head)
        {
            int pe = BitConverter.ToInt32(head, 0x3C);
            int count = BitConverter.ToUInt16(head, pe + 6), opt = BitConverter.ToUInt16(head, pe + 20);
            Base = BitConverter.ToInt64(head, pe + 24 + 24);
            for (int i = 0; i < count; i++)
            {
                int o = pe + 24 + opt + i * 40;
                string name = System.Text.Encoding.ASCII.GetString(head, o, 8).TrimEnd('\0');
                var s = new Section { Name = name, Size = BitConverter.ToUInt32(head, o + 8), Rva = BitConverter.ToUInt32(head, o + 12) };
                Sections.Add(s);
                Size = Math.Max(Size, s.Rva + s.Size);
            }
        }

        public Section SectionOf(long rva)
        {
            foreach (var s in Sections) if (rva >= s.Rva && rva < s.Rva + s.Size) return s;
            return null;
        }

        public long ReadInt64(long rva) { return BitConverter.ToInt64(Read(rva, 8), 0); }
        public int ReadInt32(long rva) { return BitConverter.ToInt32(Read(rva, 4), 0); }
    }

    // A dump made by the capture tools (classic_re poll dumps): the image laid out by RVA, ImageBase = the runtime base.
    public sealed class DumpImage : GameImage
    {
        readonly byte[] data;
        public DumpImage(string path)
        {
            data = File.ReadAllBytes(path);
            ParseHeaders(data);
        }
        public override byte[] Read(long rva, int count)
        {
            var b = new byte[count];
            if (rva >= 0 && rva < data.Length) Buffer.BlockCopy(data, (int)rva, b, 0, (int)Math.Min(count, data.Length - rva));
            return b;
        }
        public byte[] ReadAbsolute(long address, int count) { return Read(address - Base, count); }
    }

    // The running client (Forever: Wow.exe, retail: WowB.exe), read with ReadProcessMemory only (nothing is written to the game).
    public sealed class LiveImage : GameImage, IDisposable
    {
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] d, UIntPtr n, out UIntPtr r);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr p);

        readonly IntPtr handle;
        public readonly int Pid;
        public readonly string ExePath, Version;

        public LiveImage(Process p)
        {
            Pid = p.Id;
            ExePath = p.MainModule.FileName;
            Version = FileVersionInfo.GetVersionInfo(ExePath).FileVersion;
            handle = OpenProcess(0x0410, false, p.Id);       // query information + read memory
            if (handle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess");
            long baseAddress = p.MainModule.BaseAddress.ToInt64();
            ParseHeaders(ReadAbsolute(baseAddress, 0x1000));
            Base = baseAddress;                               // the PE header holds the preferred base, not the real one
        }

        public byte[] ReadAbsolute(long address, int count)
        {
            var b = new byte[count];
            // read page by page so one unreadable page does not lose the rest
            int done = 0;
            while (done < count)
            {
                long a = address + done;
                int chunk = (int)Math.Min(count - done, 0x1000 - (a & 0xFFF));
                var part = new byte[chunk];
                UIntPtr got;
                if (ReadProcessMemory(handle, new IntPtr(a), part, new UIntPtr((uint)chunk), out got))
                    Buffer.BlockCopy(part, 0, b, done, (int)got.ToUInt64());
                done += chunk;
            }
            return b;
        }

        public override byte[] Read(long rva, int count) { return ReadAbsolute(Base + rva, count); }

        public void Dispose() { CloseHandle(handle); }

        // The Forever client runs as Wow.exe (_forever_\Wow.exe), retail as WowB.exe - try both. A process whose modules cannot be
        // read (elevated game, unelevated tool) is skipped instead of failing the search, and the reason is kept in LastError.
        public static readonly string[] Names = { "Wow", "WowB", "WowClassic", "WowClassicB", "WowT" };
        public static string LastError;

        public static Process FindClient()
        {
            LastError = null;
            bool seen = false;
            foreach (var name in Names)
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    seen = true;
                    try { var _ = p.MainModule.BaseAddress; return p; }
                    catch (Win32Exception ex) { LastError = name + ".exe (PID " + p.Id + "): " + ex.Message; }
                    catch (InvalidOperationException) { }
                }
            }
            if (!seen) LastError = "no " + string.Join(" / ", Names) + " process found";
            return null;
        }
    }
}
