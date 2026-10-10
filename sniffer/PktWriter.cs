// Writes the same PKT 3.1 files as Ymir, so WowPacketParser, Ymir Tool's viewer and classic_re/sniff read them unchanged:
//   header: "PKT", uint16 0x0301, uint8 sniffer 0x17, uint32 build, 4-char locale, 40-byte session key (zeros), uint32 start unix time,
//           uint32 start tick (0), uint32 optional header size (6) + optional header: 03 01 + int32 UTC offset in seconds
//   record: "SMSG"/"CMSG", uint32 connection index, uint32 tick (ms since the first packet), uint32 extra size (9),
//           uint32 data size, extra (double unix time in ms + 0), data (uint32 opcode + payload, decrypted and decompressed)
using System;
using System.IO;
using System.Text;

namespace ForeverSniffer
{
    public sealed class PktWriter : IDisposable
    {
        readonly FileStream file;
        readonly BinaryWriter w;
        readonly long startMicros;
        public long Records;
        DateTime lastFlush = DateTime.UtcNow;

        public PktWriter(string path, int build, string locale, long startMicros)
        {
            this.startMicros = startMicros;
            file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            w = new BinaryWriter(file);
            w.Write(Encoding.ASCII.GetBytes("PKT"));
            w.Write((ushort)0x0301);
            w.Write((byte)0x17);
            w.Write(build);
            w.Write(Encoding.ASCII.GetBytes((locale + "enUS").Substring(0, 4)));
            w.Write(new byte[40]);
            w.Write((uint)(startMicros / 1000000));
            w.Write(0u);
            w.Write(6);
            w.Write((byte)0x03);
            w.Write((byte)0x01);
            w.Write((int)TimeZoneInfo.Local.GetUtcOffset(DateTime.Now).TotalSeconds);
            w.Flush();
        }

        public void Write(bool fromServer, int connection, long unixMicros, byte[] data)
        {
            w.Write(Encoding.ASCII.GetBytes(fromServer ? "SMSG" : "CMSG"));
            w.Write(connection);
            w.Write((uint)Math.Max(0, (unixMicros - startMicros) / 1000));
            w.Write(9);
            w.Write(data.Length);
            w.Write(unixMicros / 1000.0);
            w.Write((byte)0);
            w.Write(data);
            ++Records;
            if ((DateTime.UtcNow - lastFlush).TotalSeconds >= 1)     // so the viewer can read the sniff while it is recorded
            {
                w.Flush();
                lastFlush = DateTime.UtcNow;
            }
        }

        public void Dispose()
        {
            w.Flush();
            file.Dispose();
        }
    }
}
