using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Crypto
{
    public class RC4Transformer : KerberosCryptoTransformer
    {
        private const int HashSize = 16;
        private const int ConfounderSize = 8;

        public override int ChecksumSize => HashSize;

        public override int BlockSize => HashSize;

        public override int KeySize => HashSize;

        public override byte[] String2Key(KerberosKey key)
        {
            return MD4(key.PasswordBytes);
        }

        private static byte[] MD4(byte[] key)
        {
            using (var md4 = new MD4())
            {
                return md4.ComputeHash(key);
            }
        }

        public override byte[] Decrypt(ReadOnlyMemory<byte> ciphertext, KerberosKey key, KeyUsage usage)
        {
            var k1 = key.GetKey(this);

            var salt = GetSalt((int)usage);

            var k2 = HMACMD5(k1, salt);

            var checksum = new byte[HashSize];

            Buffer.BlockCopy(ciphertext.ToArray(), 0, checksum, 0, HashSize);

            var k3 = HMACMD5(k2, checksum);

            var ciphertextOffset = new byte[ciphertext.Length - HashSize];

            Buffer.BlockCopy(ciphertext.ToArray(), HashSize, ciphertextOffset, 0, ciphertextOffset.Length);

            var plaintext = RC4.Transform(k3, ciphertextOffset);

            var calculatedHmac = HMACMD5(k2, plaintext);

            if (!AreEqualSlow(calculatedHmac, ciphertext.ToArray(), calculatedHmac.Length))
            {
                throw new SecurityException("Invalid Checksum");
            }

            var output = new byte[plaintext.Length - ConfounderSize];

            Buffer.BlockCopy(plaintext, ConfounderSize, output, 0, output.Length);

            return output;
        }

        public override byte[] MakeChecksum(byte[] key, byte[] data, KeyUsage keyUsage)
        {
            var ksign = HMACMD5(key, Encoding.ASCII.GetBytes("signaturekey\0"));

            var tmp = MD5(ConvertToLittleEndian((int)keyUsage).Concat(data).ToArray());

            return HMACMD5(ksign, tmp);
        }

        private static byte[] ConvertToLittleEndian(int thing)
        {
            byte[] bytes = new byte[4];

            Endian.ConvertToLittleEndian(thing, bytes, 0);

            return bytes;
        }

        private static byte[] MD5(byte[] data)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
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

        private static byte[] HMACMD5(byte[] key, byte[] data)
        {
            using (HMACMD5 hmac = new HMACMD5(key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
}