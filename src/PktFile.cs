// Ymir PKT 3.1 sniff files (classic_re/sniff/pkt.py): header, then per packet direction ("CMSG"/"SMSG"), connection, tick, extra
// header size, length, extra bytes, data (Classic opcode as the first 4 bytes).
//
// The file can still be growing (Ymir records into it): it is opened shared, Refresh() reads only the new bytes, a packet that
// is not completely written yet waits for the next Refresh, and a file that got shorter (replaced) is read again from the start.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace YmirTool
{
    public struct PacketInfo
    {
        public int Offset;          // start of the payload (after the opcode) in the buffer
        public int Length;          // payload length
        public uint Opcode;
        public bool FromServer;
        public uint Connection;
        public int TimeMs;          // since the start of the sniff
    }

    public sealed class PktFile
    {
        public readonly string Path;
        public int Build;
        public DateTime Started;
        public readonly List<PacketInfo> Packets = new List<PacketInfo>();
        public string Problem;      // why parsing stopped early (damaged file), or null

        byte[] buf = new byte[1 << 20];
        int length;                 // bytes of the file in buf
        int parsePos = -1;          // next packet header (-1 = file header not read yet)
        uint startTick;

        PktFile(string path) { Path = path; }

        public static PktFile Open(string path)
        {
            var f = new PktFile(path);
            f.Refresh();
            if (f.parsePos < 0) throw new InvalidDataException(f.Problem ?? "not a PKT file (or still empty)");
            return f;
        }

        // Reads what was added to the file since the last call; returns the number of new packets.
        public int Refresh()
        {
            long size;
            using (var fs = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                size = fs.Length;
                if (size < length) { Reset(); }                 // the file was replaced or cut: start over
                if (size > int.MaxValue - 1) throw new InvalidDataException("file larger than 2 GB");
                if (size > length)
                {
                    if (size > buf.Length) Array.Resize(ref buf, (int)Math.Max(size, Math.Min((long)buf.Length * 2, int.MaxValue - 1)));
                    fs.Position = length;
                    while (length < size)
                    {
                        int n = fs.Read(buf, length, (int)(size - length));
                        if (n <= 0) break;
                        length += n;
                    }
                }
            }
            int before = Packets.Count;
            Parse();
            return Packets.Count - before;
        }

        void Reset()
        {
            length = 0; parsePos = -1; Packets.Clear(); Problem = null;
        }

        void Parse()
        {
            if (parsePos < 0)
            {
                const int fixedHeader = 3 + 2 + 1 + 4 + 4 + 40 + 12;
                if (length < fixedHeader) return;
                if (buf[0] != 'P' || buf[1] != 'K' || buf[2] != 'T') { Problem = "not a PKT file"; return; }
                Build = BitConverter.ToInt32(buf, 6);
                int pos = 3 + 2 + 1 + 4 + 4 + 40;
                uint startTime = BitConverter.ToUInt32(buf, pos);
                startTick = BitConverter.ToUInt32(buf, pos + 4);
                int optLen = BitConverter.ToInt32(buf, pos + 8);
                if (optLen < 0 || optLen > 1 << 20) { Problem = "damaged file header"; return; }
                if (length < fixedHeader + optLen) return;
                Started = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(startTime).ToLocalTime();
                parsePos = fixedHeader + optLen;
            }
            while (parsePos + 20 <= length)
            {
                int pos = parsePos;
                bool server = buf[pos] == 'S';
                if (!(buf[pos] == 'S' || buf[pos] == 'C') || buf[pos + 1] != 'M' || buf[pos + 2] != 'S' || buf[pos + 3] != 'G')
                {
                    Problem = string.Format("damaged packet header at byte {0:N0}; packets after it are not shown", pos);
                    parsePos = int.MaxValue / 2;            // stop for good
                    return;
                }
                uint conn = BitConverter.ToUInt32(buf, pos + 4), tick = BitConverter.ToUInt32(buf, pos + 8);
                int extra = BitConverter.ToInt32(buf, pos + 12), len = BitConverter.ToInt32(buf, pos + 16);
                if (extra < 0 || len < 0 || extra > 1 << 20 || len > 64 << 20)
                {
                    Problem = string.Format("damaged packet size at byte {0:N0}; packets after it are not shown", pos);
                    parsePos = int.MaxValue / 2;
                    return;
                }
                long end = (long)pos + 20 + extra + len;
                if (end > length) return;                  // not completely written yet
                int data = pos + 20 + extra;
                var p = new PacketInfo { FromServer = server, Connection = conn, TimeMs = unchecked((int)(tick - startTick)) };
                if (len >= 4) { p.Opcode = BitConverter.ToUInt32(buf, data); p.Offset = data + 4; p.Length = len - 4; }
                else { p.Offset = data; p.Length = 0; }
                Packets.Add(p);
                parsePos = (int)end;
            }
        }

        public byte[] Payload(PacketInfo p, int max)
        {
            int n = Math.Min(p.Length, max);
            var b = new byte[n];
            Buffer.BlockCopy(buf, p.Offset, b, 0, n);
            return b;
        }

        // Position of 'pattern' in the packet payload, or -1 (ASCII letters compared without case when ignoreCase)
        public int Find(PacketInfo p, byte[] pattern, bool ignoreCase)
        {
            int last = p.Offset + p.Length - pattern.Length;
            for (int i = p.Offset; i <= last; i++)
            {
                int j = 0;
                for (; j < pattern.Length; j++)
                {
                    byte a = buf[i + j], b = pattern[j];
                    if (a == b) continue;
                    if (ignoreCase && a >= 'A' && a <= 'Z' && a + 32 == b) continue;
                    if (ignoreCase && a >= 'a' && a <= 'z' && a - 32 == b) continue;
                    break;
                }
                if (j == pattern.Length) return i - p.Offset;
            }
            return -1;
        }

        public static string HexDump(byte[] b, int total, int markStart, int markLength)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < b.Length; i += 16)
            {
                sb.AppendFormat("{0:X6}  ", i);
                for (int j = 0; j < 16; j++)
                {
                    int k = i + j;
                    bool mark = markLength > 0 && k >= markStart && k < markStart + markLength;     // search match: "AB*"
                    sb.Append(k < b.Length ? b[k].ToString("X2") + (mark ? "*" : " ") : "   ");
                }
                sb.Append("  ");
                for (int j = 0; j < 16 && i + j < b.Length; j++) sb.Append(b[i + j] >= 32 && b[i + j] < 127 ? (char)b[i + j] : '.');
                sb.AppendLine();
            }
            if (total > b.Length) sb.AppendLine(string.Format("... {0:N0} more bytes", total - b.Length));
            return sb.ToString();
        }

        // what Ymir writes in the header without reading the whole file: build and start time
        public static bool PeekHeader(string path, out int build, out DateTime started)
        {
            build = 0; started = DateTime.MinValue;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    var h = new byte[58];
                    if (fs.Read(h, 0, h.Length) < h.Length || h[0] != 'P' || h[1] != 'K' || h[2] != 'T') return false;
                    build = BitConverter.ToInt32(h, 6);
                    started = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(BitConverter.ToUInt32(h, 54)).ToLocalTime();
                    return true;
                }
            }
            catch { return false; }
        }
    }

    public static class Opcodes
    {
        static Dictionary<uint, string> server, client;

        static void Load()
        {
            server = new Dictionary<uint, string>(); client = new Dictionary<uint, string>();
            foreach (var line in Resources.Text("opcodes.txt").Split('\n'))
            {
                var p = line.Trim().Split(' ');
                if (p.Length != 3) continue;
                (p[0] == "S" ? server : client)[Convert.ToUInt32(p[1], 16)] = p[2];
            }
        }

        public static string Name(uint opcode, bool fromServer)
        {
            if (server == null) Load();
            string n;
            return (fromServer ? server : client).TryGetValue(opcode, out n) ? n : "";
        }

        public static int Count { get { if (server == null) Load(); return server.Count + client.Count; } }
    }

    public static class Resources
    {
        public static string Text(string name)
        {
            using (var s = typeof(Resources).Assembly.GetManifestResourceStream("YmirTool." + name))
            using (var r = new StreamReader(s, Encoding.UTF8))
                return r.ReadToEnd();
        }
    }
}
