// One world server connection (the realm connection, and the instance connection the client opens after SMSG_CONNECT_TO).
//
// Wire format (TrinityCore WorldSocket): first a text line "WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT - V2\n" (and the client
// one), then packets: uint32 size + 12-byte AES-GCM tag + size bytes (uint32 opcode + payload). The first packet each way is plain:
// server AUTH_CHALLENGE (challenge at payload 32..63), client AUTH_SESSION (about 1 KB, challenge at payload 20..51) or
// AUTH_CONTINUED_SESSION (80 bytes: uint64 DosResponse, challenge at 8..39, digest, ...). A few more plain packets follow until each side switches to encryption; the switch is found by
// the tag check (only the right key and counter make the tag match). Opcodes are never needed, so new client builds do not matter here.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace ForeverSniffer
{
    public sealed class WirePacket
    {
        public bool FromServer;
        public byte[] Tag;
        public byte[] Data;         // opcode + payload (encrypted until decrypted)
        public long UnixMicros;
        public ulong Index;         // number of the packet in its direction, from 0: the AES-GCM counter (it counts the plain
                                    // handshake packets too, TrinityCore WorldPacketCrypt increments it for every packet)
    }

    public sealed class WorldConnection
    {
        public const string Banner = "WORLD OF WARCRAFT CONNECTION";

        sealed class Side
        {
            public readonly TcpStream Tcp = new TcpStream();
            public readonly List<byte> Buffer = new List<byte>();
            public bool BannerDone, Encrypted, GotFirst;
            public int Packets;
        }

        public readonly int Index;
        public readonly string ClientEnd, ServerEnd;
        readonly Side client = new Side(), server = new Side();
        readonly Inflater inflater = new Inflater();
        readonly List<WirePacket> pending = new List<WirePacket>();
        readonly Action<WorldConnection, WirePacket> output;
        readonly Action<string> log;
        byte[] serverChallenge, clientChallenge;
        WorldCrypt crypt;
        int decryptFailures, inflateFailures;
        public bool Continued;      // opened after SMSG_CONNECT_TO (AUTH_CONTINUED_SESSION)
        public int Type;            // 0 realm, 1 instance (SMSG_CONNECT_TO connection type): Ymir writes it as the connection index
        public bool Searched;
        uint connectionGroup;       // high 16 bits of this build's connection messages (from AUTH_CHALLENGE)
        WirePacket heldChallenge;       // the memory search ran for this connection (at most once)
        public bool Broken;

        public WorldConnection(int index, string clientEnd, string serverEnd, Action<WorldConnection, WirePacket> output, Action<string> log)
        {
            Index = index; ClientEnd = clientEnd; ServerEnd = serverEnd; this.output = output; this.log = log;
        }

        public bool HasKey { get { return crypt != null; } }
        public bool NeedsKey { get { return crypt == null && serverChallenge != null && clientChallenge != null && pending.Count > 0; } }
        // capture time of the oldest packet this connection still holds back (no key yet, or the challenge waiting for the client)
        public long HeldSinceMicros
        {
            get
            {
                long t = long.MaxValue;
                if (crypt == null && pending.Count > 0 && !Broken) t = pending[0].UnixMicros;
                if (heldChallenge != null) t = Math.Min(t, heldChallenge.UnixMicros);
                return t;
            }
        }
        public bool Closed { get { return client.Tcp.Closed && server.Tcp.Closed; } }
        public int PacketCount { get { return client.Packets + server.Packets; } }
        public int DecryptFailures { get { return decryptFailures; } }

        public void Add(TcpSegment s, bool fromServer)
        {
            var side = fromServer ? server : client;
            side.Tcp.Add(s, (bytes, micros) => OnBytes(side, fromServer, bytes, micros));
        }

        void OnBytes(Side side, bool fromServer, byte[] bytes, long micros)
        {
            if (Broken) return;
            side.Buffer.AddRange(bytes);
            if (!side.BannerDone)
            {
                int nl = side.Buffer.IndexOf((byte)'\n');
                if (nl < 0) return;
                side.Buffer.RemoveRange(0, nl + 1);
                side.BannerDone = true;
            }
            while (side.Buffer.Count >= 16)
            {
                int size = side.Buffer[0] | (side.Buffer[1] << 8) | (side.Buffer[2] << 16) | (side.Buffer[3] << 24);
                if (size < 4 || size > (16 << 20))
                {
                    log(string.Format("connection {0}: bad packet size {1}, stream lost (capture dropped data?)", Index, size));
                    Broken = true;
                    return;
                }
                if (side.Buffer.Count < 16 + size) return;
                var p = new WirePacket { FromServer = fromServer, Tag = side.Buffer.GetRange(4, 12).ToArray(), Data = side.Buffer.GetRange(16, size).ToArray(), UnixMicros = micros, Index = (ulong)side.Packets };
                side.Buffer.RemoveRange(0, 16 + size);
                side.Packets++;
                OnPacket(side, p);
            }
        }

        void OnPacket(Side side, WirePacket p)
        {
            if (!side.GotFirst)
            {
                side.GotFirst = true;
                if (p.FromServer && p.Data.Length >= 4 + 64)
                {
                    serverChallenge = Slice(p.Data, 4 + 32, 32);
                    connectionGroup = BitConverter.ToUInt32(p.Data, 0) & 0xFFFF0000;    // AUTH_CHALLENGE = index 0 of the connection group
                }
                else if (!p.FromServer && p.Data.Length >= 4 + 40 && p.Data.Length < 4 + 200)
                {
                    clientChallenge = Slice(p.Data, 4 + 8, 32);
                    Continued = true;
                    // the key of the SMSG_CONNECT_TO this connection answers (payload 64..71, after the uint64 DosResponse, challenge and 24-byte digest) gives its connection type
                    int type;
                    Type = p.Data.Length >= 4 + 72 && ConnectToTypes.TryGetValue(BitConverter.ToUInt64(p.Data, 4 + 64), out type) ? type : 1;
                }
                else if (!p.FromServer && p.Data.Length >= 4 + 52) clientChallenge = Slice(p.Data, 4 + 20, 32);
                // the server's challenge waits for the client's answer, which tells the connection type
                if (p.FromServer) { heldChallenge = p; return; }
                if (heldChallenge != null) { output(this, heldChallenge); heldChallenge = null; }
                output(this, p);
                return;
            }
            if (crypt == null) { pending.Add(p); return; }
            Process(p);
        }

        void Process(WirePacket p)
        {
            var side = p.FromServer ? server : client;
            uint magic = p.FromServer ? WorldCrypt.ServerMagic : WorldCrypt.ClientMagic;
            if (!side.Encrypted)
            {
                // still plain until the first packet whose tag matches
                if (crypt.Decrypt(p.Index, magic, p.Data, 0, p.Data.Length, p.Tag)) side.Encrypted = true;
            }
            else if (!crypt.Decrypt(p.Index, magic, p.Data, 0, p.Data.Length, p.Tag))
            {
                if (decryptFailures++ == 0) log(string.Format("connection {0}: a packet did not decrypt (lost capture data?)", Index));
                return;
            }
            if (p.FromServer) Unpack(p, 0);
            else output(this, p);
        }

        // Ymir writes the packets inside SMSG_COMPRESSED_PACKET (connection group index 0x0E) and SMSG_MULTIPLE_PACKETS (0x0D), not the
        // containers; the group comes from AUTH_CHALLENGE, so it follows the client build. Each container is also checked by its layout.
        void Unpack(WirePacket p, int depth)
        {
            uint opcode = p.Data.Length >= 4 ? BitConverter.ToUInt32(p.Data, 0) : 0;
            if (depth < 4 && connectionGroup != 0 && opcode == (connectionGroup | 0x0E))
            {
                var inner = Decompress(p.Data);
                if (inner != null) { Unpack(Copy(p, inner), depth + 1); return; }
            }
            if (depth < 4 && connectionGroup != 0 && opcode == (connectionGroup | 0x0D))
            {
                var parts = SplitMultiple(p.Data);
                if (parts != null) { foreach (var part in parts) Unpack(Copy(p, part), depth + 1); return; }
            }
            // SMSG_CONNECT_TO (connection group index 0x08): uint32 payload count, uint32 serial, uint8 connection type, uint64 key, ...
            if (connectionGroup != 0 && opcode == (connectionGroup | 0x08) && p.Data.Length >= 4 + 17)
                ConnectToTypes[BitConverter.ToUInt64(p.Data, 4 + 9)] = p.Data[4 + 8];
            output(this, p);
        }

        // connect-to key -> connection type (0 realm, 1 instance), for the connections the client opens next
        public static readonly Dictionary<ulong, int> ConnectToTypes = new Dictionary<ulong, int>();

        static WirePacket Copy(WirePacket p, byte[] data)
        {
            return new WirePacket { FromServer = p.FromServer, Tag = p.Tag, Data = data, UnixMicros = p.UnixMicros, Index = p.Index };
        }

        // SMSG_COMPRESSED_PACKET: opcode, uint32 uncompressed size, uint32 adler32 of the uncompressed data, uint32 adler32 of the
        // deflate data (both adler32 start from 0x9827D8F1, TrinityCore WorldSocket), deflate data -> opcode + payload, or null.
        const uint AdlerSeed = 0x9827D8F1;
        byte[] Decompress(byte[] d)
        {
            if (d.Length < 16) return null;
            uint size = BitConverter.ToUInt32(d, 4), uncompressedAdler = BitConverter.ToUInt32(d, 8), compressedAdler = BitConverter.ToUInt32(d, 12);
            if (size < 4 || size > (64 << 20) || Inflater.Adler32(d, 16, d.Length - 16, AdlerSeed) != compressedAdler) return null;
            try
            {
                var inner = inflater.Inflate(d, 16, d.Length - 16);
                if (inner.Length != size || Inflater.Adler32(inner, 0, inner.Length, AdlerSeed) != uncompressedAdler)
                    if (inflateFailures++ == 0) log(string.Format("connection {0}: a compressed packet did not unpack to its checksum", Index));
                return inner;
            }
            catch (InvalidDataException e)
            {
                if (inflateFailures++ == 0) log(string.Format("connection {0}: a compressed packet could not be unpacked: {1}", Index, e.Message));
                return null;
            }
        }

        // SMSG_MULTIPLE_PACKETS: opcode, then [uint16 payload size][uint32 opcode][payload] until the end; null if it does not add up
        static List<byte[]> SplitMultiple(byte[] d)
        {
            var parts = new List<byte[]>();
            int pos = 4;
            while (pos < d.Length)
            {
                if (pos + 6 > d.Length) return null;
                int len = BitConverter.ToUInt16(d, pos);
                if (pos + 2 + 4 + len > d.Length) return null;
                parts.Add(Slice(d, pos + 2, 4 + len));
                pos += 2 + 4 + len;
            }
            return parts.Count > 0 ? parts : null;
        }

        // --unpack: a decrypted packet from an older sniff of this connection goes through the same unpacking as a live one
        public void Replay(WirePacket p)
        {
            if (p.FromServer && connectionGroup == 0 && p.Data.Length >= 4) connectionGroup = BitConverter.ToUInt32(p.Data, 0) & 0xFFFF0000;
            if (p.FromServer) Unpack(p, 0);
            else output(this, p);
        }

        // the packets a key is tested on (copies, so a search on another thread can use them)
        public List<WirePacket> Samples()
        {
            var list = new List<WirePacket>();
            foreach (var p in pending)
            {
                list.Add(new WirePacket { FromServer = p.FromServer, Tag = p.Tag, Data = (byte[])p.Data.Clone(), UnixMicros = p.UnixMicros, Index = p.Index });
                if (list.Count >= 8) break;
            }
            return list;
        }

        public byte[] ServerChallenge { get { return serverChallenge; } }
        public byte[] ClientChallenge { get { return clientChallenge; } }

        // true when the session key decrypts one of the samples
        public static bool KeyWorks(byte[] sessionKey, byte[] clientChallenge, byte[] serverChallenge, List<WirePacket> samples)
        {
            using (var c = new WorldCrypt(WorldCrypt.DeriveKey(sessionKey, clientChallenge, serverChallenge)))
            {
                foreach (var p in samples)
                {
                    var copy = (byte[])p.Data.Clone();
                    if (c.Decrypt(p.Index, p.FromServer ? WorldCrypt.ServerMagic : WorldCrypt.ClientMagic, copy, 0, copy.Length, p.Tag)) return true;
                }
            }
            return false;
        }

        public bool TryKey(byte[] sessionKey)
        {
            if (!KeyWorks(sessionKey, clientChallenge, serverChallenge, Samples())) return false;
            crypt = new WorldCrypt(WorldCrypt.DeriveKey(sessionKey, clientChallenge, serverChallenge));
            foreach (var p in pending) Process(p);
            pending.Clear();
            return true;
        }

        public void FlushUndecrypted()
        {
            if (pending.Count > 0) log(string.Format("connection {0}: {1} packets could not be decrypted (no session key), left out", Index, pending.Count));
            pending.Clear();
        }

        static byte[] Slice(byte[] d, int offset, int length)
        {
            var r = new byte[length];
            Buffer.BlockCopy(d, offset, r, 0, length);
            return r;
        }

        public static bool StartsWithBanner(byte[] payload)
        {
            return payload.Length >= Banner.Length && Encoding.ASCII.GetString(payload, 0, Banner.Length) == Banner;
        }

        public static bool IsServerBanner(byte[] payload)
        {
            return Encoding.ASCII.GetString(payload, 0, Math.Min(payload.Length, 80)).Contains("SERVER TO CLIENT");
        }
    }
}
