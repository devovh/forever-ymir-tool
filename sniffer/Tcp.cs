// Frames -> TCP segments -> in-order byte streams (one per direction), with retransmissions and out-of-order segments handled.
using System;
using System.Collections.Generic;

namespace ForeverSniffer
{
    public sealed class TcpSegment
    {
        public string Source, Destination;      // "ip:port"
        public uint Seq;
        public bool Syn, Fin, Rst;
        public byte[] Payload;
        public long UnixMicros;
    }

    public static class Frames
    {
        // link types: 0 NULL/loopback (Npcap loopback adapter), 1 Ethernet, 12/14/101 raw IP, 113 Linux cooked
        public static TcpSegment Parse(CapturedFrame f)
        {
            byte[] d = f.Data;
            int o;
            switch (f.LinkType)
            {
                case 0: o = 4; break;
                case 1:
                {
                    o = 14;
                    int type = d.Length >= 14 ? (d[12] << 8) | d[13] : 0;
                    while ((type == 0x8100 || type == 0x88A8) && d.Length >= o + 4) { type = (d[o + 2] << 8) | d[o + 3]; o += 4; }
                    if (type != 0x0800 && type != 0x86DD) return null;
                    break;
                }
                case 12: case 14: case 101: o = 0; break;
                case 113: o = 16; break;
                default: return null;
            }
            if (d.Length < o + 20) return null;

            string src, dst;
            int tcp, end;
            int version = d[o] >> 4;
            if (version == 4)
            {
                int ihl = (d[o] & 0x0F) * 4;
                if (d[o + 9] != 6) return null;
                if ((((d[o + 6] & 0x1F) << 8) | d[o + 7]) != 0 || (d[o + 6] & 0x20) != 0) return null;  // fragments: not used by WoW
                int total = (d[o + 2] << 8) | d[o + 3];
                end = Math.Min(d.Length, o + (total > 0 ? total : d.Length - o));
                src = string.Format("{0}.{1}.{2}.{3}", d[o + 12], d[o + 13], d[o + 14], d[o + 15]);
                dst = string.Format("{0}.{1}.{2}.{3}", d[o + 16], d[o + 17], d[o + 18], d[o + 19]);
                tcp = o + ihl;
            }
            else if (version == 6)
            {
                if (d.Length < o + 40 || d[o + 6] != 6) return null;
                int payload = (d[o + 4] << 8) | d[o + 5];
                end = Math.Min(d.Length, o + 40 + payload);
                src = Ip6(d, o + 8);
                dst = Ip6(d, o + 24);
                tcp = o + 40;
            }
            else return null;

            if (end < tcp + 20) return null;
            int sport = (d[tcp] << 8) | d[tcp + 1], dport = (d[tcp + 2] << 8) | d[tcp + 3];
            uint seq = (uint)((d[tcp + 4] << 24) | (d[tcp + 5] << 16) | (d[tcp + 6] << 8) | d[tcp + 7]);
            int dataOffset = (d[tcp + 12] >> 4) * 4;
            byte flags = d[tcp + 13];
            int start = tcp + dataOffset;
            if (start > end) return null;
            var payloadBytes = new byte[end - start];
            Buffer.BlockCopy(d, start, payloadBytes, 0, payloadBytes.Length);
            return new TcpSegment
            {
                Source = src + ":" + sport, Destination = dst + ":" + dport, Seq = seq,
                Syn = (flags & 0x02) != 0, Fin = (flags & 0x01) != 0, Rst = (flags & 0x04) != 0,
                Payload = payloadBytes, UnixMicros = f.UnixMicros,
            };
        }

        static string Ip6(byte[] d, int o)
        {
            var parts = new string[8];
            for (int i = 0; i < 8; ++i) parts[i] = ((d[o + 2 * i] << 8) | d[o + 2 * i + 1]).ToString("x");
            return "[" + string.Join(":", parts) + "]";
        }
    }

    // One direction of a TCP connection: delivers the bytes in order.
    public sealed class TcpStream
    {
        bool synced;
        uint next;                                              // next expected sequence number
        readonly SortedDictionary<uint, TcpSegment> early = new SortedDictionary<uint, TcpSegment>();
        public bool Closed;

        public void Add(TcpSegment s, Action<byte[], long> deliver)
        {
            if (s.Rst || s.Fin) Closed = true;
            if (s.Syn) { synced = true; next = s.Seq + 1; return; }
            if (s.Payload.Length == 0) return;
            if (!synced) { synced = true; next = s.Seq; }

            int ahead = (int)(s.Seq - next);
            if (ahead > 0)
            {
                if (early.Count < 4096 && !early.ContainsKey(s.Seq)) early[s.Seq] = s;
                return;
            }
            Take(s, deliver);
            while (early.Count > 0)
            {
                bool progressed = false;
                foreach (var kv in early)
                {
                    if ((int)(kv.Key - next) <= 0)
                    {
                        early.Remove(kv.Key);
                        Take(kv.Value, deliver);
                        progressed = true;
                        break;
                    }
                    break;      // sorted by sequence number: nothing else can fit yet (wrap-around aside)
                }
                if (!progressed) break;
            }
        }

        void Take(TcpSegment s, Action<byte[], long> deliver)
        {
            int skip = (int)(next - s.Seq);                     // already delivered part (retransmission)
            if (skip >= s.Payload.Length) return;
            byte[] data = s.Payload;
            if (skip > 0)
            {
                data = new byte[s.Payload.Length - skip];
                Buffer.BlockCopy(s.Payload, skip, data, 0, data.Length);
            }
            next += (uint)data.Length;
            deliver(data, s.UnixMicros);
        }
    }
}
