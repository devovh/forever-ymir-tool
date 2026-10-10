// World packet crypto of the 1.60 client (same as TrinityCore WorldPacketCrypt): AES-256-GCM, 12-byte tag in the packet header,
// IV = 64-bit packet counter + "CLNT" (client to server) or "SRVR" (server to client). Windows BCrypt does the AES-GCM, because
// .NET Framework 4.8 has no AesGcm class.
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ForeverSniffer
{
    public sealed class WorldCrypt : IDisposable
    {
        public const uint ClientMagic = 0x544E4C43, ServerMagic = 0x52565253;

        // TrinityCore WorldSocket::EncryptionKeySeed
        static readonly byte[] EncryptionKeySeed = { 0x71, 0xC9, 0xED, 0x5A, 0xA7, 0x0E, 0x4D, 0xFF, 0x4C, 0x36, 0xA6, 0x5A, 0x3E, 0x46, 0x8A, 0x4A,
                                                     0x5D, 0xA1, 0x48, 0xC8, 0x30, 0x47, 0x4A, 0xDE, 0xF6, 0x0D, 0x6C, 0xBE, 0x6F, 0xE4, 0x55, 0x73 };

        // encrypt key = first 32 bytes of HMAC-SHA512(session key, client challenge + server challenge + seed)
        public static byte[] DeriveKey(byte[] sessionKey, byte[] clientChallenge, byte[] serverChallenge)
        {
            using (var hmac = new HMACSHA512(sessionKey))
            {
                var input = new byte[clientChallenge.Length + serverChallenge.Length + EncryptionKeySeed.Length];
                Buffer.BlockCopy(clientChallenge, 0, input, 0, clientChallenge.Length);
                Buffer.BlockCopy(serverChallenge, 0, input, clientChallenge.Length, serverChallenge.Length);
                Buffer.BlockCopy(EncryptionKeySeed, 0, input, clientChallenge.Length + serverChallenge.Length, EncryptionKeySeed.Length);
                var digest = hmac.ComputeHash(input);
                var key = new byte[32];
                Buffer.BlockCopy(digest, 0, key, 0, 32);
                return key;
            }
        }

        IntPtr alg, key;

        public WorldCrypt(byte[] key32)
        {
            Check(BCryptOpenAlgorithmProvider(out alg, "AES", null, 0), "BCryptOpenAlgorithmProvider");
            byte[] mode = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            Check(BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0), "BCryptSetProperty");
            Check(BCryptGenerateSymmetricKey(alg, out key, IntPtr.Zero, 0, key32, key32.Length, 0), "BCryptGenerateSymmetricKey");
        }

        // Decrypts data in place when the tag matches; false (data unchanged) when it does not.
        public bool Decrypt(ulong counter, uint magic, byte[] data, int offset, int length, byte[] tag)
        {
            var nonce = new byte[12];
            Buffer.BlockCopy(BitConverter.GetBytes(counter), 0, nonce, 0, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(magic), 0, nonce, 8, 4);
            var input = new byte[length];
            Buffer.BlockCopy(data, offset, input, 0, length);
            var output = new byte[Math.Max(length, 1)];

            GCHandle hNonce = GCHandle.Alloc(nonce, GCHandleType.Pinned), hTag = GCHandle.Alloc(tag, GCHandleType.Pinned);
            try
            {
                var info = new AuthInfo
                {
                    cbSize = Marshal.SizeOf(typeof(AuthInfo)), dwInfoVersion = 1,
                    pbNonce = hNonce.AddrOfPinnedObject(), cbNonce = 12,
                    pbTag = hTag.AddrOfPinnedObject(), cbTag = tag.Length,
                };
                int written;
                uint status = BCryptDecrypt(key, input, length, ref info, null, 0, output, length, out written, 0);
                if (status != 0) return false;      // 0xC000A002 = STATUS_AUTH_TAG_MISMATCH
                Buffer.BlockCopy(output, 0, data, offset, length);
                return true;
            }
            finally { hNonce.Free(); hTag.Free(); }
        }

        public void Dispose()
        {
            if (key != IntPtr.Zero) { BCryptDestroyKey(key); key = IntPtr.Zero; }
            if (alg != IntPtr.Zero) { BCryptCloseAlgorithmProvider(alg, 0); alg = IntPtr.Zero; }
        }

        static void Check(uint status, string what)
        {
            if (status != 0) throw new CryptographicException(what + " failed: 0x" + status.ToString("X8"));
        }

        [StructLayout(LayoutKind.Sequential)]
        struct AuthInfo     // BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize, dwInfoVersion;
            public IntPtr pbNonce; public int cbNonce;
            public IntPtr pbAuthData; public int cbAuthData;
            public IntPtr pbTag; public int cbTag;
            public IntPtr pbMacContext; public int cbMacContext;
            public int cbAAD; public long cbData; public int dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] static extern uint BCryptOpenAlgorithmProvider(out IntPtr alg, string id, string impl, int flags);
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] static extern uint BCryptSetProperty(IntPtr obj, string property, byte[] input, int size, int flags);
        [DllImport("bcrypt.dll")] static extern uint BCryptGenerateSymmetricKey(IntPtr alg, out IntPtr key, IntPtr keyObject, int keyObjectSize, byte[] secret, int secretSize, int flags);
        [DllImport("bcrypt.dll")] static extern uint BCryptDecrypt(IntPtr key, byte[] input, int inputSize, ref AuthInfo padding, byte[] iv, int ivSize, byte[] output, int outputSize, out int result, int flags);
        [DllImport("bcrypt.dll")] static extern uint BCryptDestroyKey(IntPtr key);
        [DllImport("bcrypt.dll")] static extern uint BCryptCloseAlgorithmProvider(IntPtr alg, int flags);
    }
}
