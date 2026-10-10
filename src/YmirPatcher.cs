// Makes a copy of Ymir (the Forever beta build 70124, regedit.exe) for another client build: the build number in five places and
// the three WowB.exe addresses (same as classic_re/ymir_patch/patch_ymir.py), and from client 70291 on nine opcode constants. Each patched value sits inside one instruction whose
// exact bytes are known; a file whose bytes differ anywhere in those instructions is refused. The original is never changed.
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace YmirTool
{
    public sealed class Spot
    {
        public readonly long FileOffset;
        public readonly string Kind;            // build, locale_index, locale_table, session
        public readonly byte[] Original;        // the whole instruction in the 70124 Ymir
        public readonly int ValueAt;            // where the 4-byte value starts in it
        public readonly string Text;
        public readonly uint NewOpcode;         // Kind "opcode": the value for client 70291 and later
        public Spot(long fileOffset, string kind, string hex, int valueAt, string text, uint newOpcode = 0)
        {
            FileOffset = fileOffset; Kind = kind; ValueAt = valueAt; Text = text; NewOpcode = newOpcode;
            Original = Enumerable.Range(0, hex.Length / 2).Select(i => Convert.ToByte(hex.Substring(i * 2, 2), 16)).ToArray();
        }
    }

    public static class YmirPatcher
    {
        public const int OriginalBuild = 70124;
        public const string OriginalSha256 = "97d0bd72ed78b6176e4011faa7da3c02775ec504eb0c7f8eec280d23e1058e5e";

        public static readonly Spot[] Spots =
        {
            new Spot(0x11a331, "build", "BAEC110100", 1, "mov edx, build (build text)"),
            new Spot(0x11a5b9, "build", "BAEC110100", 1, "mov edx, build (.pkt header)"),
            new Spot(0x11ba3a, "build", "3DEC110100", 1, "cmp eax, build (WowB.exe version check)"),
            new Spot(0x11ce45, "build", "BAEC110100", 1, "mov edx, build (build text)"),
            new Spot(0x11d2bd, "build", "BAEC110100", 1, "mov edx, build (build text)"),
            new Spot(0x11c206, "locale_index", "4881C2C40BFA05", 3, "add rdx, locale index"),
            new Spot(0x11c222, "locale_table", "488D940AC0F39604", 4, "lea rdx, [rdx+rcx+locale table]"),
            new Spot(0x11e2a0, "session", "4881C208E1FF05", 3, "add rdx, session key object"),
            // Client 70291 inserted a message group before the connection groups: server connection 0x4D -> 0x4E, client connection
            // 0x45 -> 0x46, server main group 0x46 -> 0x47 with one more message from about index 0x1B6 on (verified 2026-10-09 on
            // the official handshake: AUTH_CHALLENGE 0x4E0000, AUTH_SESSION 0x460001, COMPRESSED_PACKET 0x4E000E)
            new Spot(0x11e989, "opcode", "81F90E004D00", 2, "cmp ecx, SMSG_COMPRESSED_PACKET", 0x4E000E),
            new Spot(0x11e991, "opcode", "81F90D004D00", 2, "cmp ecx, SMSG_MULTIPLE_PACKETS", 0x4E000D),
            new Spot(0x11ebc2, "opcode", "81FF08004D00", 2, "cmp edi, SMSG_CONNECT_TO", 0x4E0008),
            new Spot(0x11eff6, "opcode", "81FF00004D00", 2, "cmp edi, SMSG_AUTH_CHALLENGE", 0x4E0000),
            new Spot(0x11f037, "opcode", "81C7FCFFB2FF", 2, "add edi, -SMSG_ENTER_ENCRYPTED_MODE (switch 0x4D0004..8)", 0xFFB1FFFC),
            new Spot(0x11f261, "opcode", "81FF0C004600", 2, "cmp edi, main group 0x0C", 0x47000C),
            new Spot(0x11f26d, "opcode", "81FFF1014600", 2, "cmp edi, main group 0x1F1", 0x4701F2),
            new Spot(0x11f87a, "opcode", "8D8F0000BBFF", 2, "lea ecx, [rdi - client connection group]", 0xFFBA0000),
            new Spot(0x11f96b, "opcode", "81FF0C004600", 2, "cmp edi, main group 0x0C", 0x47000C),
        };

        public static string Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
        }

        // null if the file is the Ymir this tool knows, else the reason
        public static string CheckSource(byte[] data)
        {
            foreach (var s in Spots)
            {
                if (s.FileOffset + s.Original.Length > data.Length) return "file too small";
                for (int i = 0; i < s.Original.Length; i++)
                    if (data[s.FileOffset + i] != s.Original[i]) return string.Format("unexpected bytes at 0x{0:x} ({1})", s.FileOffset, s.Text);
            }
            return null;
        }

        public static byte[] Patch(byte[] source, int build, BuildAddresses a)
        {
            string why = CheckSource(source);
            if (why != null) throw new InvalidOperationException(why);
            var d = (byte[])source.Clone();
            foreach (var s in Spots)
            {
                if (s.Kind == "opcode" && build < 70291)
                    continue;
                long value = s.Kind == "opcode" ? s.NewOpcode : s.Kind == "build" ? build : a.Get(s.Kind);
                Array.Copy(BitConverter.GetBytes((uint)value), 0, d, s.FileOffset + s.ValueAt, 4);
            }
            // like patch_ymir.py: the old build number must be gone completely
            var old = BitConverter.GetBytes((uint)OriginalBuild);
            for (int i = 0; i + 4 <= d.Length; i++)
                if (d[i] == old[0] && d[i + 1] == old[1] && d[i + 2] == old[2] && d[i + 3] == old[3])
                    throw new InvalidOperationException("build 70124 still present at 0x" + i.ToString("x"));
            return d;
        }

        public static string OutputPath(string source, int build)
        {
            return Path.Combine(Path.GetDirectoryName(source), Path.GetFileNameWithoutExtension(source) + "_" + build + ".exe");
        }
    }
}
