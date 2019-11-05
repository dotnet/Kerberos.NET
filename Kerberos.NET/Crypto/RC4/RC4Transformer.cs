using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public class RC4Transformer : KerberosCryptoTransformer
    {
        private const int HashSize = 16;
        private const int ConfounderSize = 8;

        public override int ChecksumSize => HashSize;

        public override int BlockSize => HashSize;

        public override int KeySize => HashSize;

        public override ReadOnlyMemory<byte> String2Key(KerberosKey key)
        {
            return MD4(key.PasswordBytes);
        }

        private static ReadOnlyMemory<byte> MD4(byte[] key)
        {
            using (var md4 = new MD4())
            {
                return md4.ComputeHash(key);
            }
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
        {
            var k1 = key.GetKey(this);

            var salt = GetSalt((int)usage);

            var k2 = HMACMD5(k1, salt);

            var confounder = GenerateRandomBytes(ConfounderSize);

            var plaintextBuffer = new byte[data.Length + confounder.Length];
            var plaintext = new Memory<byte>(plaintextBuffer);

            confounder.CopyTo(plaintext);
            data.CopyTo(plaintext.Slice(confounder.Length));

            var checksum = HMACMD5(k2, plaintextBuffer);

            var k3 = HMACMD5(k2, checksum);

            var ciphertext = new Memory<byte>(new byte[plaintext.Length + checksum.Length]);

            RC4.Transform(k3.Span, plaintext.Span, ciphertext.Span.Slice(checksum.Length));

            checksum.CopyTo(ciphertext);

            return ciphertext;
        }

        public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> ciphertext, KerberosKey key, KeyUsage usage)
        {
            var k1 = key.GetKey(this);

            var salt = GetSalt((int)usage);

            var k2 = HMACMD5(k1, salt);

            var checksum = ciphertext.Slice(0, HashSize);

            var k3 = HMACMD5(k2, checksum);

            var ciphertextOffset = ciphertext.Slice(HashSize);

            var plaintext = new Memory<byte>(new byte[ciphertextOffset.Length]);

            RC4.Transform(k3.Span, ciphertextOffset.Span, plaintext.Span);

            var actualChecksum = HMACMD5(k2, plaintext);

            if (!AreEqualSlow(checksum.Span, ciphertext.Span.Slice(0, actualChecksum.Length)))
            {
                throw new SecurityException("Invalid Checksum");
            }

            return plaintext.Slice(ConfounderSize);
        }

        private static readonly ReadOnlyMemory<byte> ChecksumSignatureKey = Encoding.ASCII.GetBytes("signaturekey\0");

        public override ReadOnlyMemory<byte> MakeChecksum(ReadOnlyMemory<byte> key, ReadOnlySpan<byte> data, KeyUsage keyUsage)
        {
            var ksign = HMACMD5(key, ChecksumSignatureKey);

            var span = new Span<byte>(new byte[4 + data.Length]);

            data.CopyTo(span.Slice(4));

            Endian.ConvertToLittleEndian((int)keyUsage, span);

            var tmp = MD5(span);

            return HMACMD5(ksign, tmp);
        }

        private static ReadOnlyMemory<byte> MD5(ReadOnlySpan<byte> data)
        {
            using (var md5 = new MD5())
            {
                return md5.ComputeHash(data);
            }
        }

        private static byte[] GetSalt(int usage)
        {
            switch (usage)
            {
                case 3:
                    usage = 8;
                    break;
                case 9:
                    usage = 8;
                    break;
                case 23:
                    usage = 13;
                    break;
            }

            var salt = new byte[4]
            {
                (byte)(usage & 0xff),
                (byte)((usage >> 8) & 0xff),
                (byte)((usage >> 16) & 0xff),
                (byte)((usage >> 24) & 0xff)
            };

            return salt;
        }

        private static ReadOnlyMemory<byte> HMACMD5(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var keyArray = TryGetArrayFast(key);
            var dataArray = TryGetArrayFast(data);

            using (HMACMD5 hmac = new HMACMD5(keyArray))
            {
                return hmac.ComputeHash(dataArray, 0, data.Length);
            }
        }
    }
}
