using System;
using System.IO;
using System.Security.Cryptography;
using AES = System.Security.Cryptography.Aes;

namespace Syfuhs.Security.Kerberos.Crypto
{
    internal static class AESCTS
    {
        public static byte[] Encrypt(byte[] plainText, byte[] key, byte[] iv)
        {
            var padSize = 16 - (plainText.Length % 16);

            if (plainText.Length < 16)
            {
                return plainText;
            }

            byte[] data;
            byte[] encrypted;

            if (padSize == 16)
            {
                if (plainText.Length > 16)
                {
                    iv = new byte[iv.Length];
                }

                data = plainText;
            }
            else
            {
                data = new byte[plainText.Length + padSize];

                Buffer.BlockCopy(plainText, 0, data, 0, plainText.Length);

                for (var i = 0; i < padSize; i++)
                {
                    data[data.Length - padSize + i] = 0;
                }
            }

            encrypted = Transform(data, key, iv, true);

            if (plainText.Length >= 32)
            {
                SwapLastTwoBlocks(encrypted);
            }

            var result = new byte[plainText.Length];

            Buffer.BlockCopy(encrypted, 0, result, 0, plainText.Length);

            return result;
        }

        private static AES algorithm;
        private static readonly object _lockAlgorithm = new object();

        private static AES Algorithm
        {
            get
            {
                if (algorithm == null)
                {
                    lock (_lockAlgorithm)
                    {
                        if (algorithm == null)
                        {
                            algorithm = new AesManaged();
                            algorithm.Padding = PaddingMode.None;
                            algorithm.Mode = CipherMode.CBC;
                        }
                    }
                }

                return algorithm;
            }
        }

        private static byte[] Transform(byte[] data, byte[] key, byte[] iv, bool encrypt)
        {
            ICryptoTransform transform;

            if (encrypt)
            {
                transform = Algorithm.CreateEncryptor(key, iv);
            }
            else
            {
                transform = Algorithm.CreateDecryptor(key, iv);
            }

            using (transform)
            using (var stream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                }

                return stream.ToArray();
            }
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            var keySize = key.Length;
            var padSize = 16 - (cipherText.Length % 16);

            if (cipherText.Length < 16)
            {
                return cipherText;
            }

            if (padSize == 16)
            {
                var data = new byte[cipherText.Length];

                Buffer.BlockCopy(cipherText, 0, data, 0, cipherText.Length);

                if (cipherText.Length >= 32)
                {
                    SwapLastTwoBlocks(data);
                }

                if (data.Length == 16)
                {
                    iv = new byte[iv.Length];
                }

                return Transform(data, key, iv, false);
            }
            else
            {
                var depadded = Depad(cipherText, padSize);

                var dn = Transform(
                    depadded,
                    key,
                    new byte[iv.Length],
                    false
                );

                var data = new byte[cipherText.Length + padSize];

                Buffer.BlockCopy(cipherText, 0, data, 0, cipherText.Length);

                Buffer.BlockCopy(dn, dn.Length - padSize, data, cipherText.Length, padSize);

                SwapLastTwoBlocks(data);

                var transformed = Transform(data, key, iv, false);

                var result = new byte[cipherText.Length];

                Buffer.BlockCopy(transformed, 0, result, 0, cipherText.Length);

                return result;
            }
        }

        private static byte[] Depad(byte[] cipherText, int padSize)
        {
            var result = new byte[16];

            var offset = cipherText.Length - 32 + padSize;

            Buffer.BlockCopy(cipherText, offset, result, 0, 16);

            return result;
        }

        private static void SwapLastTwoBlocks(byte[] data)
        {
            for (var i = 0; i < 16; i++)
            {
                byte temp = data[i + data.Length - 32];

                data[i + data.Length - 32] = data[i + data.Length - 16];
                data[i + data.Length - 16] = temp;
            }
        }
    }
}
