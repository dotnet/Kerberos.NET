using Kerberos.NET.Entities;
using System;
using System.Security;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public abstract class AESTransformer : KerberosCryptoTransformer
    {
        private readonly AESEncryptor encryptor;
        private readonly IHasher hasher;

        protected AESTransformer(AESEncryptor encryptor, IHasher hasher)
        {
            this.encryptor = encryptor;
            this.hasher = hasher;
        }

        public override int ChecksumSize { get { return 96 / 8; } }

        protected virtual byte[] DecryptWith(byte[] workBuffer, int[] workLens, byte[] key, byte[] iv, KeyUsage usage)
        {
            var confounderLen = workLens[0];
            var checksumLen = workLens[1];
            var dataLen = workLens[2];

            byte[] Ki;
            byte[] Ke;

            var constant = new byte[5];

            Endian.ConvertToBigEndian((int)usage, constant, 0);

            constant[4] = 170;

            Ke = encryptor.DK(key, constant);

            constant[4] = 85;

            Ki = encryptor.DK(key, constant);

            var tmpEnc = new byte[confounderLen + dataLen];
            Buffer.BlockCopy(workBuffer, 0, tmpEnc, 0, (confounderLen + dataLen));

            var checksum = new byte[checksumLen];

            Buffer.BlockCopy(workBuffer, confounderLen + dataLen, checksum, 0, checksumLen);

            encryptor.Decrypt(Ke, iv, tmpEnc);

            var newChecksum = MakeChecksum(Ki, tmpEnc, checksumLen, 0);

            if (!AreEqualSlow(checksum, newChecksum))
            {
                throw new SecurityException("Invalid checksum");
            }

            var data = new byte[dataLen];

            Buffer.BlockCopy(tmpEnc, confounderLen, data, 0, dataLen);

            return data;
        }

        public override byte[] Decrypt(byte[] cipher, KerberosKey key, KeyUsage usage)
        {
            var iv = new byte[encryptor.BlockSize];
            return Decrypt(cipher, key.GetKey(encryptor), iv, usage);
        }

        public override byte[] MakeChecksum(byte[] key, byte[] data, int hashSize, int keyUsage = 0)
        {
            var hash = hasher.Hmac(key, data);

            var output = new byte[hashSize];

            Buffer.BlockCopy(hash, 0, output, 0, hashSize);

            return output;
        }

        private byte[] Decrypt(byte[] cipher, byte[] key, byte[] iv, KeyUsage usage)
        {
            var totalLen = cipher.Length;
            var confounderLen = encryptor.BlockSize;
            var checksumLen = ChecksumSize;
            var dataLen = totalLen - (confounderLen + checksumLen);

            var lengths = new int[] { confounderLen, checksumLen, dataLen };

            return DecryptWith(cipher, lengths, key, iv, usage);
        }
    }
}
