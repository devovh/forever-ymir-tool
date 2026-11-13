// Confirms a session key slot cryptographically instead of by byte pattern.
//
// The patterns (fingerprints) only say "these bytes look like a locale table" - on a new client layout they stop matching and the
// search cannot tell a real hit from noise. ForeverSniffer already solves this the reliable way: take a captured packet, derive the
// AES-256-GCM key from a candidate session key, and check the authentication tag. A wrong key cannot pass. This file brings the
// same check to Ymir Tool: the crypt primitives are the sniffer's own (sniffer\Crypto.cs), compiled into this tool unchanged.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace YmirTool
{
    /// <summary>One captured packet that a candidate session key can be tried against.</summary>
    public sealed class KeySample
    {
        public bool FromServer;
        public byte[] Tag;          // the 12 bytes from the wire header
        public byte[] Data;         // ciphertext as it came off the wire
        public ulong Index;         // packet number in its direction = the AES-GCM counter
        public int Connection;      // which world connection this packet belongs to (each one has its own key)
        public byte[] ClientChallenge, ServerChallenge;
    }

    public static class KeyCheck
    {
        public const int SessionKeyOffset = 0x48, SessionKeySize = 40;
        const int MinDistinct = 30;      // 40 random bytes never repeat this little; heap objects full of pointers do

        public static bool IsPointer(long v) { return v >= 0x10000000000L && v < 0x7ff000000000L; }

        /// <summary>The key at pointer + 0x48, or null when that is not a real (random looking) key.</summary>
        public static byte[] ReadKeyAt(GameImage img, long pointer)
        {
            if (!IsPointer(pointer)) return null;
            byte[] k;
            try { k = img.Read(pointer + SessionKeyOffset - img.Base, SessionKeySize); }
            catch { return null; }
            if (k == null || k.Length != SessionKeySize || k.Distinct().Count() < MinDistinct) return null;
            return k;
        }

        /// <summary>
        /// Reads the key with a short run of extra bytes behind it. On some builds the object is not exactly 0x48 bytes,
        /// so the real key starts a few bytes off; trying a small window finds it without knowing the layout.
        /// </summary>
        public static byte[] ReadKeyWindow(GameImage img, long pointer, int back, out int actualOffset)
        {
            actualOffset = SessionKeyOffset;
            if (!IsPointer(pointer)) return null;
            byte[] raw;
            try { raw = img.Read(pointer + SessionKeyOffset - back - img.Base, SessionKeySize + 2 * back); }
            catch { return null; }
            if (raw == null || raw.Length < SessionKeySize + 2 * back) return null;
            for (int i = 0; i <= 2 * back; i++)
            {
                var k = new byte[SessionKeySize];
                Buffer.BlockCopy(raw, i, k, 0, SessionKeySize);
                if (k.Distinct().Count() < MinDistinct) continue;
                actualOffset = SessionKeyOffset - back + i;
                return k;
            }
            return null;
        }

        /// <summary>
        /// Every 8-byte .data slot that holds a pointer into the image, read straight from a dump file.
        /// Not via GameImage: its Read() returns zeros past the end of a section, so a slot at the very end of the
        /// dump silently became "pointer 0" and the key search tried nothing at all.
        /// </summary>
        public static List<KeyValuePair<long, long>> SlotsFromDump(string dumpPath, out long imageBase, out long imageSize)
        {
            var data = File.ReadAllBytes(dumpPath);
            int pe = BitConverter.ToInt32(data, 0x3C);
            int count = BitConverter.ToUInt16(data, pe + 6), opt = BitConverter.ToUInt16(data, pe + 20);
            imageBase = BitConverter.ToInt64(data, pe + 24 + 24);
            long size = BitConverter.ToUInt32(data, pe + 24 + 56);
            imageSize = size;

            var slots = new List<KeyValuePair<long, long>>();
            var seen = new HashSet<long>();
            for (int i = 0; i < count; i++)
            {
                int o = pe + 24 + opt + i * 40;
                string name = System.Text.Encoding.ASCII.GetString(data, o, 8).TrimEnd('\0');
                if (name != ".data") continue;
                long rva = BitConverter.ToUInt32(data, o + 12);
                long vsize = BitConverter.ToUInt32(data, o + 8);
                long end = Math.Min(rva + vsize, data.Length);
                for (long off = rva; off + 8 <= end; off += 8)
                {
                    long v = BitConverter.ToInt64(data, (int)off);
                    if (v < imageBase || v >= imageBase + size) continue;
                    if (!seen.Add(v)) continue;
                    slots.Add(new KeyValuePair<long, long>(off, v));
                }
            }
            return slots;
        }

        /// <summary>Reads the key window straight from a dump file - no GameImage, no zero padding, no per-read allocation.</summary>
        public static byte[] ReadKeyFromDump(string dumpPath, long pointer, int back, out int actualOffset)
        {
            actualOffset = SessionKeyOffset;
            byte[] b;
            try { b = File.ReadAllBytes(dumpPath); } catch { return null; }
            return ReadKeyFromBytes(b, pointer, back, out actualOffset);
        }

        public static byte[] ReadKeyFromBytes(byte[] b, long pointer, int back, out int actualOffset)
        {
            actualOffset = SessionKeyOffset;
            // a dump is indexed by RVA, so the absolute pointer must lose the image base first
            long rva = pointer - ImageBaseOf(b);
            if (rva < 0) return null;
            long at = rva + SessionKeyOffset - back;
            if (at < 0 || at + SessionKeySize + 2 * back > b.Length) return null;
            for (int i = 0; i <= 2 * back; i++)
            {
                var k = new byte[SessionKeySize];
                Buffer.BlockCopy(b, (int)(at + i), k, 0, SessionKeySize);
                if (k.Distinct().Count() < MinDistinct) continue;
                actualOffset = SessionKeyOffset - back + i;
                return k;
            }
            return null;
        }

        static long cachedBase = long.MinValue;
        static byte[] cachedBytes;

        /// <summary>The image base recorded in a dump's PE header.</summary>
        public static long ImageBaseOf(byte[] b)
        {
            if (!ReferenceEquals(cachedBytes, b))
            {
                int pe = BitConverter.ToInt32(b, 0x3C);
                cachedBase = BitConverter.ToInt64(b, pe + 24 + 24);
                cachedBytes = b;
            }
            return cachedBase;
        }

        /// <summary>The pointer slots of a dump, as absolute values - read once, no GameImage (whose Read returns zeros).</summary>
        public static List<KeyValuePair<long, long>> SlotsFromBytes(byte[] b, out long imageBase, out long imageSize)
        {
            int pe = BitConverter.ToInt32(b, 0x3C);
            int count = BitConverter.ToUInt16(b, pe + 6), opt = BitConverter.ToUInt16(b, pe + 20);
            imageBase = BitConverter.ToInt64(b, pe + 24 + 24);
            imageSize = BitConverter.ToUInt32(b, pe + 24 + 56);

            var slots = new List<KeyValuePair<long, long>>();
            var seen = new HashSet<long>();
            for (int i = 0; i < count; i++)
            {
                int o = pe + 24 + opt + i * 40;
                string name = System.Text.Encoding.ASCII.GetString(b, o, 8).TrimEnd((char)0);
                if (name != ".data") continue;
                long rva = BitConverter.ToUInt32(b, o + 12);
                long vsize = BitConverter.ToUInt32(b, o + 8);
                long end = Math.Min(rva + vsize, b.Length);
                for (long off = rva; off + 8 <= end; off += 8)
                {
                    long v = BitConverter.ToInt64(b, (int)off);
                    if (v < imageBase || v >= imageBase + imageSize) continue;
                    if (!seen.Add(v)) continue;
                    slots.Add(new KeyValuePair<long, long>(off, v));
                }
            }
            return slots;
        }

        /// <summary>True when this key decrypts at least one captured packet (AES-GCM tag check).</summary>
        public static bool Works(byte[] sessionKey, IEnumerable<KeySample> samples)
        {
            if (sessionKey == null || sessionKey.Length != SessionKeySize) return false;
            foreach (var s in samples)
            {
                if (s.ClientChallenge == null || s.ServerChallenge == null) continue;
                try
                {
                    using (var c = new ForeverSniffer.WorldCrypt(ForeverSniffer.WorldCrypt.DeriveKey(sessionKey, s.ClientChallenge, s.ServerChallenge)))
                    {
                        var copy = (byte[])s.Data.Clone();
                        if (c.Decrypt(s.Index, s.FromServer ? ForeverSniffer.WorldCrypt.ServerMagic : ForeverSniffer.WorldCrypt.ClientMagic,
                                      copy, 0, copy.Length, s.Tag))
                            return true;
                    }
                }
                catch { }
            }
            return false;
        }
    }

    /// <summary>
    /// Reads the challenges and the first packets out of a .pkt sniff, so a candidate key can be tried on real traffic.
    /// Offsets follow ForeverSniffer's WorldConnection.OnPacket: the server's AUTH_CHALLENGE carries it at 4+32, the client's
    /// answer at 4+8 (or 4+20 for the longer auth packet).
    /// </summary>
    public static class PktSamples
    {
        public static List<KeySample> Load(string pktPath, out string detail)
        {
            detail = null;
            var file = PktFile.Open(pktPath);
            var perConn = new Dictionary<int, List<KeySample>>();
            // the AES-GCM counter is per DIRECTION over the whole capture, not per connection: a second connection does not
            // restart it, so counting per connection made every packet of the second one fail its tag check
            var nextIndex = new ulong[2];
            var cc = new Dictionary<int, byte[]>();
            var sc = new Dictionary<int, byte[]>();

            foreach (var p in file.Packets)
            {
                // the wire tag and the packet counter are not in PacketInfo; they sit 12 bytes before the payload in the record
                if (p.Offset < 12) continue;
                byte[] tag = file.ReadAt(p.Offset - 12, 12);
                if (tag == null) continue;
                var body = file.Payload(p, p.Length);
                if (body == null || body.Length < 4) continue;

                int conn = (int)p.Connection;
                List<KeySample> list;
                if (!perConn.TryGetValue(conn, out list)) perConn[conn] = list = new List<KeySample>();
                var sample = new KeySample { FromServer = p.FromServer, Tag = tag, Data = body, Index = nextIndex[p.FromServer ? 1 : 0]++, Connection = conn };
                list.Add(sample);

                if (p.FromServer && !sc.ContainsKey(conn) && body.Length >= 4 + 64) sc[conn] = Slice(body, 4 + 32, 32);
                if (!p.FromServer && !cc.ContainsKey(conn))
                {
                    if (body.Length >= 4 + 40 && body.Length < 4 + 200) cc[conn] = Slice(body, 4 + 8, 32);
                    else if (body.Length >= 4 + 52) cc[conn] = Slice(body, 4 + 20, 32);
                }
            }

            var result = new List<KeySample>();
            foreach (var kv in perConn)
            {
                byte[] c, s;
                cc.TryGetValue(kv.Key, out c);
                sc.TryGetValue(kv.Key, out s);
                if (c == null || s == null) continue;
                // enough packets to test a key, few enough to try thousands of candidates quickly
                foreach (var k in kv.Value.Where(x => x.Data.Length >= 8 && x.Data.Length <= 0x4000).OrderBy(x => x.Index).Take(8))
                {
                    k.ClientChallenge = c;
                    k.ServerChallenge = s;
                    result.Add(k);
                }
            }
            detail = string.Format("{0} packet(s) from {1} connection(s), challenges {2}",
                                   result.Count, perConn.Count, cc.Count > 0 && sc.Count > 0 ? "found" : "MISSING");
            return result;
        }

        static byte[] Slice(byte[] d, int offset, int length)
        {
            var r = new byte[length];
            if (offset < d.Length) Buffer.BlockCopy(d, offset, r, 0, Math.Min(length, d.Length - offset));
            return r;
        }
    }
}
