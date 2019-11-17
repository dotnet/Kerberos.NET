using System;
using System.IO;
using System.Security.Cryptography;

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
           ReadOnlySpan<byte> data,
           ReadOnlySpan<byte> key,
           ReadOnlySpan<byte> iv,
           bool encrypt
       )
        {
            var keyArray = key.ToArray();
            var ivArray = iv.ToArray();
            var dataArray = data.ToArray();

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

        public Memory<byte> Decrypt(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv
        )
        {
            return Transform(data, key, iv, false);
        }

        public Memory<byte> Encrypt(
            ReadOnlySpan<byte> data,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv
        )
        {
            return Transform(data, key, iv, true);
        }
    }
}
