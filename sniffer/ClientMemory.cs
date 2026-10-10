// Reads the world session key out of the running game client (read only, like Ymir).
//
// Fast path: the client keeps a pointer to its session object at a fixed image address; the 40-byte key sits at +0x48. The address
// changes with every client build: it comes from Ymir Tool (built-in builds and the ones it learned in %APPDATA%\YmirTool\builds.txt).
// Fallback for a build nobody has measured yet: every pointer in the image's .data section is followed and every 40-byte window of
// the objects it points to is tried. A candidate is only accepted when it decrypts a real captured packet (AES-GCM tag check), so a
// wrong key can never be used.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace ForeverSniffer
{
    public sealed class GameClient : IDisposable
    {
        public static readonly string[] ProcessNames = { "WowB", "WowClassicB", "WowClassic", "Wow", "WowT" };

        // build -> RVA of the session object pointer (same table as Ymir Tool's Finder.KnownBuilds)
        static readonly Dictionary<int, long> BuiltInSessionRva = new Dictionary<int, long>
        {
            { 70124, 0x5ffe108 }, { 70170, 0x5f519d8 }, { 70205, 0x5f52d08 }, { 70235, 0x5f644d8 }, { 70245, 0x5f65518 },
            { 70291, 0x5ffd0f8 }, { 70334, 0x5e7a098 }, { 70338, 0x5e7a098 },
        };
        public const int SessionKeyOffset = 0x48, SessionKeySize = 40;

        public Process Process;
        public int Build;
        public string Version, GameDir;
        IntPtr handle;
        long imageBase;

        public static GameClient Find()
        {
            foreach (var name in ProcessNames)
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try
                    {
                        var c = new GameClient { Process = p };
                        var info = p.MainModule.FileVersionInfo;
                        // the numeric version fields of WowB.exe are not the build (160.1.7033.4); the text is "1.60.1.70334"
                        c.Version = info.FileVersion;
                        int build;
                        c.Build = int.TryParse((info.FileVersion ?? "").Split('.').Last(), out build) ? build : 0;
                        c.GameDir = Path.GetDirectoryName(p.MainModule.FileName);
                        c.imageBase = p.MainModule.BaseAddress.ToInt64();
                        c.handle = OpenProcess(0x0010 | 0x0400, false, p.Id);       // VM_READ | QUERY_INFORMATION
                        if (c.handle == IntPtr.Zero) throw new Win32Exception();
                        return c;
                    }
                    catch (Win32Exception) { }
                    catch (InvalidOperationException) { }
                }
            }
            return null;
        }

        public bool HasExited { get { try { return Process.HasExited; } catch { return true; } } }

        // "enUS" etc. from WTF\Config.wtf (textLocale), enUS if not set
        public string Locale()
        {
            try
            {
                foreach (var line in File.ReadAllLines(Path.Combine(GameDir, "WTF", "Config.wtf")))
                    if (line.StartsWith("SET textLocale ", StringComparison.OrdinalIgnoreCase))
                    {
                        string v = line.Substring(15).Trim().Trim('"');
                        if (v.Length == 4) return v;
                    }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return "enUS";
        }

        public byte[] Read(long address, int size)
        {
            var buf = new byte[size];
            IntPtr read;
            if (!ReadProcessMemory(handle, new IntPtr(address), buf, new IntPtr(size), out read) || read.ToInt64() != size) return null;
            return buf;
        }

        long ReadPointer(long address)
        {
            var b = Read(address, 8);
            return b == null ? 0 : BitConverter.ToInt64(b, 0);
        }

        public long KnownSessionRva()
        {
            long rva;
            if (BuiltInSessionRva.TryGetValue(Build, out rva)) return rva;
            try
            {
                string learned = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "YmirTool", "builds.txt");
                foreach (var line in File.ReadAllLines(learned))
                {
                    var p = line.Split(' ');
                    if (p.Length >= 5 && p[0] == "build" && p[1] == Build.ToString()) return Convert.ToInt64(p[4], 16);
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            return 0;
        }

        // the key at the known address (null if the build is unknown or the client is not logged in yet)
        public byte[] SessionKeyAtKnownAddress()
        {
            long rva = KnownSessionRva();
            if (rva == 0) return null;
            long obj = ReadPointer(imageBase + rva);
            return IsPointer(obj) ? Read(obj + SessionKeyOffset, SessionKeySize) : null;
        }

        static bool IsPointer(long v) { return v >= 0x10000000000L && v < 0x7ff000000000L; }

        // Fallback search; accept(key) decides. Returns the key and where it was found, or null.
        public byte[] SearchSessionKey(Func<byte[], bool> accept, Action<string> log)
        {
            var hdr = Read(imageBase, 0x1000);
            if (hdr == null) return null;
            int pe = BitConverter.ToInt32(hdr, 0x3C);
            int sections = BitConverter.ToUInt16(hdr, pe + 6), optSize = BitConverter.ToUInt16(hdr, pe + 20);
            long dataRva = 0; int dataSize = 0;
            for (int i = 0; i < sections; ++i)
            {
                int o = pe + 24 + optSize + i * 40;
                if (System.Text.Encoding.ASCII.GetString(hdr, o, 5) == ".data") { dataSize = BitConverter.ToInt32(hdr, o + 8); dataRva = BitConverter.ToUInt32(hdr, o + 12); }
            }
            if (dataRva == 0) return null;

            var slots = new List<KeyValuePair<long, long>>();       // rva of the slot -> object address
            var seen = new HashSet<long>();
            const int chunk = 1 << 20;
            for (int off = 0; off < dataSize; off += chunk)
            {
                var b = Read(imageBase + dataRva + off, Math.Min(chunk, dataSize - off));
                if (b == null) continue;
                for (int i = 0; i + 8 <= b.Length; i += 8)
                {
                    long v = BitConverter.ToInt64(b, i);
                    if (IsPointer(v) && seen.Add(v)) slots.Add(new KeyValuePair<long, long>(dataRva + off + i, v));
                }
            }
            log(string.Format("searching the session key: {0} objects behind .data pointers (known slot RVA 0x{1:x} {2})", slots.Count, KnownSessionRva(),
                slots.Any(sl => sl.Key == KnownSessionRva()) ? "is among them" : "is not among them"));

            // the layout Ymir knows first (key at +0x48), then every other 8-byte aligned offset
            var offsets = new List<int> { SessionKeyOffset };
            for (int o = 0; o <= 0x1F8; o += 8) if (o != SessionKeyOffset) offsets.Add(o);
            var objects = new Dictionary<long, byte[]>();
            foreach (int keyOffset in offsets)
            {
                foreach (var slot in slots)
                {
                    byte[] obj;
                    if (!objects.TryGetValue(slot.Value, out obj)) { obj = Read(slot.Value, 0x220); objects[slot.Value] = obj; }
                    if (obj == null) continue;
                    if (obj.Skip(keyOffset).Take(SessionKeySize).Distinct().Count() < 30) continue;   // a key looks random
                    var key = new byte[SessionKeySize];
                    Buffer.BlockCopy(obj, keyOffset, key, 0, SessionKeySize);
                    if (accept(key))
                    {
                        log(string.Format("session key found: pointer at image RVA 0x{0:x}, key at +0x{1:x} (build {2})", slot.Key, keyOffset, Build));
                        return key;
                    }
                }
                if (keyOffset == SessionKeyOffset) log("not at +0x48 of any object, trying the other offsets");
            }
            log(string.Format("session key search: no 40-byte window of {0} objects decrypts the connection", objects.Count));
            return null;
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
        }

        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, IntPtr size, out IntPtr read);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    }
}
