// Raw deflate decoder for SMSG_COMPRESSED_PACKET. The server keeps one deflate stream per connection and ends every packet with
// Z_SYNC_FLUSH, so each packet holds whole deflate blocks, but they may refer back into earlier packets: the 32 KB window is kept
// between calls. Decoding follows zlib's reference decoder "puff" (Mark Adler).
using System;
using System.IO;

namespace ForeverSniffer
{
    public sealed class Inflater
    {
        const int MaxBits = 15, WindowSize = 32768;
        readonly byte[] window = new byte[WindowSize];
        int windowPos;          // next write position in the ring
        long total;             // bytes produced so far (how far back a distance may reach)

        byte[] input; int inPos, inEnd; int bitBuf, bitCount;
        MemoryStream output;

        public byte[] Inflate(byte[] data, int offset, int length)
        {
            input = data; inPos = offset; inEnd = offset + length; bitBuf = 0; bitCount = 0;
            output = new MemoryStream();
            // whole blocks until the input is used up (a sync flush ends with an empty stored block, byte aligned)
            while (inPos < inEnd || bitCount >= 3)
            {
                int last = Bits(1);
                int type = Bits(2);
                if (type == 0) Stored();
                else if (type == 1) Codes(FixedLength, FixedDistance);
                else if (type == 2) Dynamic();
                else throw new InvalidDataException("bad deflate block type");
                if (last == 1) break;
                if (inPos >= inEnd && bitCount < 8 && (bitBuf & ((1 << bitCount) - 1)) == 0) break;   // only padding left
            }
            return output.ToArray();
        }

        int Bits(int need)
        {
            int val = bitBuf;
            while (bitCount < need)
            {
                if (inPos >= inEnd) throw new InvalidDataException("deflate data ends early");
                val |= input[inPos++] << bitCount;
                bitCount += 8;
            }
            bitBuf = val >> need;
            bitCount -= need;
            return val & ((1 << need) - 1);
        }

        void Put(byte b)
        {
            output.WriteByte(b);
            window[windowPos] = b;
            windowPos = (windowPos + 1) & (WindowSize - 1);
            ++total;
        }

        void Stored()
        {
            bitBuf = 0; bitCount = 0;       // to a byte boundary
            if (inPos + 4 > inEnd) throw new InvalidDataException("stored block header cut");
            int len = input[inPos] | (input[inPos + 1] << 8);
            int nlen = input[inPos + 2] | (input[inPos + 3] << 8);
            inPos += 4;
            if (len != (~nlen & 0xFFFF)) throw new InvalidDataException("stored block length check failed");
            if (inPos + len > inEnd) throw new InvalidDataException("stored block cut");
            for (int i = 0; i < len; ++i) Put(input[inPos++]);
        }

        sealed class Huffman
        {
            public readonly short[] Count = new short[MaxBits + 1];
            public readonly short[] Symbol;
            public Huffman(int symbols) { Symbol = new short[symbols]; }
        }

        static int Construct(Huffman h, short[] length, int offset, int n)
        {
            Array.Clear(h.Count, 0, h.Count.Length);
            for (int s = 0; s < n; ++s) h.Count[length[offset + s]]++;
            if (h.Count[0] == n) return 0;
            int left = 1;
            for (int len = 1; len <= MaxBits; ++len) { left <<= 1; left -= h.Count[len]; if (left < 0) return left; }
            var offs = new short[MaxBits + 1];
            for (int len = 1; len < MaxBits; ++len) offs[len + 1] = (short)(offs[len] + h.Count[len]);
            for (int s = 0; s < n; ++s) if (length[offset + s] != 0) h.Symbol[offs[length[offset + s]]++] = (short)s;
            return left;
        }

        int Decode(Huffman h)
        {
            int code = 0, first = 0, index = 0;
            for (int len = 1; len <= MaxBits; ++len)
            {
                code |= Bits(1);
                int count = h.Count[len];
                if (code - count < first) return h.Symbol[index + (code - first)];
                index += count; first += count; first <<= 1; code <<= 1;
            }
            throw new InvalidDataException("bad huffman code");
        }

        static readonly short[] LengthBase = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
        static readonly short[] LengthExtra = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
        static readonly short[] DistBase = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
        static readonly short[] DistExtra = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

        void Codes(Huffman lencode, Huffman distcode)
        {
            while (true)
            {
                int symbol = Decode(lencode);
                if (symbol < 256) { Put((byte)symbol); continue; }
                if (symbol == 256) return;
                symbol -= 257;
                if (symbol >= 29) throw new InvalidDataException("bad length symbol");
                int len = LengthBase[symbol] + Bits(LengthExtra[symbol]);
                int ds = Decode(distcode);
                if (ds >= 30) throw new InvalidDataException("bad distance symbol");
                int dist = DistBase[ds] + Bits(DistExtra[ds]);
                if (dist > total || dist > WindowSize) throw new InvalidDataException("distance too far back");
                for (int i = 0; i < len; ++i) Put(window[(windowPos - dist) & (WindowSize - 1)]);
            }
        }

        static readonly Huffman FixedLength, FixedDistance;
        static Inflater()
        {
            var lengths = new short[288];
            for (int s = 0; s < 144; ++s) lengths[s] = 8;
            for (int s = 144; s < 256; ++s) lengths[s] = 9;
            for (int s = 256; s < 280; ++s) lengths[s] = 7;
            for (int s = 280; s < 288; ++s) lengths[s] = 8;
            FixedLength = new Huffman(288);
            Construct(FixedLength, lengths, 0, 288);
            var dist = new short[30];
            for (int s = 0; s < 30; ++s) dist[s] = 5;
            FixedDistance = new Huffman(30);
            Construct(FixedDistance, dist, 0, 30);
        }

        static readonly short[] Order = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

        void Dynamic()
        {
            int nlen = Bits(5) + 257, ndist = Bits(5) + 1, ncode = Bits(4) + 4;
            if (nlen > 286 || ndist > 30) throw new InvalidDataException("bad dynamic block counts");
            var lengths = new short[320];
            for (int i = 0; i < ncode; ++i) lengths[Order[i]] = (short)Bits(3);
            var lencode = new Huffman(288);
            if (Construct(lencode, lengths, 0, 19) != 0) throw new InvalidDataException("bad code length code");
            int index = 0;
            while (index < nlen + ndist)
            {
                int symbol = Decode(lencode);
                if (symbol < 16) { lengths[index++] = (short)symbol; continue; }
                short len = 0; int repeat;
                if (symbol == 16)
                {
                    if (index == 0) throw new InvalidDataException("repeat with no first length");
                    len = lengths[index - 1];
                    repeat = 3 + Bits(2);
                }
                else if (symbol == 17) repeat = 3 + Bits(3);
                else repeat = 11 + Bits(7);
                if (index + repeat > nlen + ndist) throw new InvalidDataException("too many lengths");
                while (repeat-- > 0) lengths[index++] = len;
            }
            if (lengths[256] == 0) throw new InvalidDataException("no end-of-block code");
            int err = Construct(lencode, lengths, 0, nlen);
            if (err < 0 || (err > 0 && nlen - lencode.Count[0] != 1)) throw new InvalidDataException("bad literal/length code");
            var distcode = new Huffman(30);
            err = Construct(distcode, lengths, nlen, ndist);
            if (err < 0 || (err > 0 && ndist - distcode.Count[0] != 1)) throw new InvalidDataException("bad distance code");
            Codes(lencode, distcode);
        }

        public static uint Adler32(byte[] data, int offset, int length, uint start = 1)
        {
            uint a = start & 0xFFFF, b = start >> 16;
            for (int i = 0; i < length; ++i)
            {
                a = (a + data[offset + i]) % 65521;
                b = (b + a) % 65521;
            }
            return (b << 16) | a;
        }
    }
}
