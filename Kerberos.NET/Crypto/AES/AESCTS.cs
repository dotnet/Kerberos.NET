using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using AESAlgorithm = System.Security.Cryptography.Aes;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal static class AESCTS
    {
        public static ReadOnlySpan<byte> Encrypt(
            ReadOnlySpan<byte> plainText,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv
        )
        {
            var padSize = 16 - (plainText.Length % 16);

            if (plainText.Length < 16)
            {
                return plainText;
            }

            Span<byte> data;
            Span<byte> encrypted;

            if (padSize == 16)
            {
                if (plainText.Length > 16)
                {
                    iv = new byte[iv.Length];
                }

                data = plainText.ToArray();
            }
            else
            {
                data = new byte[plainText.Length + padSize];

                plainText.CopyTo(data);

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

            return encrypted.Slice(0, plainText.Length);
        }

        private static AESAlgorithm algorithm;
        private static readonly object _lockAlgorithm = new object();

        private static AESAlgorithm Algorithm
        {
            get
            {
                if (algorithm == null)
                {
                    lock (_lockAlgorithm)
                    {
                        if (algorithm == null)
                        {
                            var impl = AESAlgorithm.Create();
                            impl.Padding = PaddingMode.None;
                            impl.Mode = CipherMode.CBC;
                            algorithm = impl;
                        }
                    }
                }

                return algorithm;
            }
        }

        private static Span<byte> Transform(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, bool encrypt)
        {
            ICryptoTransform transform;

            if (encrypt)
            {
                transform = Algorithm.CreateEncryptor(key.ToArray(), iv.ToArray());
            }
            else
            {
                transform = Algorithm.CreateDecryptor(key.ToArray(), iv.ToArray());
            }

            using (transform)
            using (var stream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(stream, transform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data.ToArray(), 0, data.Length);
                }

                return stream.ToArray();
            }
        }

        public static ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
        {
            var padSize = 16 - (ciphertext.Length % 16);

            if (ciphertext.Length < 16)
            {
                return ciphertext;
            }

            if (padSize == 16)
            {
                var data = new Span<byte>(new byte[ciphertext.Length]);

                ciphertext.CopyTo(data);

                if (ciphertext.Length >= 32)
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
                var depadded = Depad(ciphertext, padSize);

                var dn = Transform(
                    depadded,
                    key,
                    new byte[iv.Length],
                    false
                );

                var data = new Span<byte>(new byte[ciphertext.Length + padSize]);

                ciphertext.CopyTo(data);

                dn.Slice(dn.Length - padSize).CopyTo(data.Slice(ciphertext.Length, padSize));

                SwapLastTwoBlocks(data);

                var transformed = Transform(data, key, iv, false);

                return transformed.Slice(0, ciphertext.Length);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlySpan<byte> Depad(ReadOnlySpan<byte> ciphertext, int padSize)
        {
            var offset = ciphertext.Length - 32 + padSize;

            return ciphertext.Slice(offset, 16);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void SwapLastTwoBlocks(Span<byte> data)
        {
            for (var i = 0; i < 16; i++)
            {
                var temp = data[i + data.Length - 32];

                data[i + data.Length - 32] = data[i + data.Length - 16];
                data[i + data.Length - 16] = temp;
            }
        }
    }
}
