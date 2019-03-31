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

        private readonly IEncryptor encryptor;

        public RC4Transformer(IEncryptor encryptor)
        {
            this.encryptor = encryptor;
        }

        public override int ChecksumSize => HashSize;

        public override byte[] Decrypt(byte[] ciphertext, KerberosKey key, KeyUsage usage)
        {
            var k1 = key.GetKey(encryptor);

            var salt = GetSalt((int)usage);

            var k2 = HMACMD5(k1, salt);

            var checksum = new byte[HashSize];

            Buffer.BlockCopy(ciphertext, 0, checksum, 0, HashSize);

            var k3 = HMACMD5(k2, checksum);

            var ciphertextOffset = new byte[ciphertext.Length - HashSize];

            Buffer.BlockCopy(ciphertext, HashSize, ciphertextOffset, 0, ciphertextOffset.Length);

            var plaintext = RC4.Decrypt(k3, ciphertextOffset);

            var calculatedHmac = HMACMD5(k2, plaintext);

            if (!AreEqualSlow(calculatedHmac, ciphertext, calculatedHmac.Length))
            {
                throw new SecurityException("Invalid Checksum");
            }

            var output = new byte[plaintext.Length - ConfounderSize];

            Buffer.BlockCopy(plaintext, ConfounderSize, output, 0, output.Length);

            return output;
        }

        public override byte[] MakeChecksum(byte[] key, byte[] data, int hashSize, int messageType = 0)
        {
            var ksign = HMACMD5(key, Encoding.ASCII.GetBytes("signaturekey\0"));

            var tmp = MD5(ConvertToLittleEndian(messageType).Concat(data).ToArray());

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
            return System.Security.Cryptography.MD5.Create().ComputeHash(data);
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
