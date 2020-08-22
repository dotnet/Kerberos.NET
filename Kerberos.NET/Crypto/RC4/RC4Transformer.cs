// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Security;
using System.Text;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    public class RC4Transformer : KerberosCryptoTransformer
    {
        private const int HashSize = 16;
        private const int ConfounderSize = 8;

        public override int ChecksumSize => HashSize;

        public override int BlockSize => HashSize;

        public override int KeySize => HashSize;

        public override ChecksumType ChecksumType => ChecksumType.KERB_CHECKSUM_HMAC_MD5;

        public override ReadOnlyMemory<byte> String2Key(KerberosKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return MD4(key.PasswordBytes);
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var k1 = key.GetKey(this);

            var salt = GetSalt((int)usage);

            var k2 = HMACMD5(k1, salt);

            var confounder = this.GenerateRandomBytes(ConfounderSize);

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
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var k1 = key.GetKey(this);

            var salt = GetSalt((int)usage);

            var k2 = HMACMD5(k1, salt);

            var incomingChecksum = ciphertext.Slice(0, HashSize);

            var k3 = HMACMD5(k2, incomingChecksum);

            var ciphertextOffset = ciphertext.Slice(HashSize);

            var plaintext = new Memory<byte>(new byte[ciphertextOffset.Length]);

            RC4.Transform(k3.Span, ciphertextOffset.Span, plaintext.Span);

            var actualChecksum = HMACMD5(k2, plaintext);

            if (!AreEqualSlow(incomingChecksum.Span, actualChecksum.Span.Slice(0, actualChecksum.Length)))
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

            BinaryPrimitives.WriteInt32LittleEndian(span, (int)keyUsage);

            var tmp = MD5(span);

            return HMACMD5(ksign, tmp);
        }

        private static byte[] GetSalt(int usage)
        {
            switch (usage)
            {
                case 3:
                    usage = 8;
                    break;
                case 23:
                    usage = 13;
                    break;
            }

            var salt = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(salt, usage);

            return salt;
        }

        private static ReadOnlyMemory<byte> MD5(ReadOnlySpan<byte> data)
        {
            using (var md5 = CryptoPal.Platform.Md5())
            {
                return md5.ComputeHash(data);
            }
        }

        private static ReadOnlyMemory<byte> HMACMD5(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> data)
        {
            var hmac = CryptoPal.Platform.HmacMd5();

            return hmac.ComputeHash(key, data);
        }

        private static ReadOnlyMemory<byte> MD4(ReadOnlyMemory<byte> key)
        {
            using (var md4 = CryptoPal.Platform.Md4())
            {
                return md4.ComputeHash(key.Span);
            }
        }
    }
#endif
}
