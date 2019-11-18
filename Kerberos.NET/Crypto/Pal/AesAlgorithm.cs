using System;
using System.IO;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;

namespace Kerberos.NET.Crypto
{
    internal class AesAlgorithm : ISymmetricAlgorithm
    {
        private static readonly Lazy<Aes> lazyAlgorithm
            = new Lazy<Aes>(() =>
            {
                var impl = Aes.Create();
                impl.Padding = PaddingMode.None;
                impl.Mode = CipherMode.CBC;
                return impl;
            });

        public static Aes Algorithm => lazyAlgorithm.Value;

        private static Memory<byte> Transform(
           ReadOnlyMemory<byte> data,
           ReadOnlyMemory<byte> key,
           ReadOnlyMemory<byte> iv,
           bool encrypt
       )
        {
            var keyArray = TryGetArrayFast(key);
            var ivArray = TryGetArrayFast(iv);
            var dataArray = TryGetArrayFast(data);

            ICryptoTransform transform;

            if (encrypt)
            {
                transform = Algorithm.CreateEncryptor(keyArray, ivArray);
            }
            else
            {
                transform = Algorithm.CreateDecryptor(keyArray, ivArray);
            }

            using (transform)
            using (var stream = new MemoryStream(data.Length))
            {
                using (var cryptoStream = new CryptoStream(
                    stream,
                    transform,
                    CryptoStreamMode.Write
                ))
                {
                    cryptoStream.Write(dataArray, 0, data.Length);
                }

                return stream.GetBuffer();
            }
        }

        public Memory<byte> Decrypt(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> iv)
        {
            return Transform(data, key, iv, false);
        }

        public Memory<byte> Encrypt(ReadOnlyMemory<byte> data, ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> iv)
        {
            return Transform(data, key, iv, true);
        }
    }
}
