using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto
{
    public static class PKInitString2Key
    {
        public static ReadOnlyMemory<byte> String2Key(
            ReadOnlySpan<byte> sharedSecret,
            int length,
            ReadOnlySpan<byte> clientNonce = default,
            ReadOnlySpan<byte> serverNonce = default)
        {
            var key = new byte[length];
            using IHashAlgorithm sha1 = CryptoPal.Platform.Sha1();

            int xSize = sharedSecret.Length + clientNonce.Length + serverNonce.Length;
            int concatSize = xSize + 1;

            byte[] xPooledArray = null;
            byte[] concatPooledArray = null;

            Span<byte> x = xSize <= 256
                ? stackalloc byte[256]
                : xPooledArray = CryptoPool.Rent(xSize);

            Span<byte> concat = concatSize <= 256
                ? stackalloc byte[256]
                : concatPooledArray = CryptoPool.Rent(concatSize);

            try
            {
                x = Concat(sharedSecret, clientNonce, serverNonce, x);

                Span<byte> fill = stackalloc byte[HashSizes.SHA1];
                sha1.ComputeHash(Concat(0, x, concat), fill, out int bytesWritten);
                Debug.Assert(bytesWritten == fill.Length);

                int position = 0;
                int count = 0;

                for (var i = 0; i < length; i++)
                {
                    int index;

                    if (position < fill.Length)
                    {
                        index = position;
                        position++;
                    }
                    else
                    {
                        count++;

                        sha1.ComputeHash(Concat((byte)count, concatSize, concat), fill, out bytesWritten);
                        Debug.Assert(bytesWritten == fill.Length);

                        index = 0;
                        position = 1;
                    }

                    key[i] = fill[index];
                }

                return key;
            }
            finally
            {
                CryptoPool.Return(xPooledArray, xSize);
                CryptoPool.Return(concatPooledArray, concatSize);
            }
        }

        private static Span<byte> Concat(
            ReadOnlySpan<byte> sharedSecret,
            ReadOnlySpan<byte> clientNonce,
            ReadOnlySpan<byte> serverNonce,
            Span<byte> dest)
        {
            int written = sharedSecret.Length + clientNonce.Length + serverNonce.Length;

            Debug.Assert(dest.Length >= written);

            sharedSecret.CopyTo(dest);
            clientNonce.CopyTo(dest.Slice(sharedSecret.Length));
            serverNonce.CopyTo(dest.Slice(sharedSecret.Length + clientNonce.Length));

            return dest.Slice(0, written);
        }

        private static Span<byte> Concat(byte count, ReadOnlySpan<byte> x, Span<byte> dest)
        {
            int written = x.Length + 1;

            Debug.Assert(dest.Length >= written);

            dest[0] = count;
            x.CopyTo(dest.Slice(1));

            return dest.Slice(0, written);
        }

        private static Span<byte> Concat(byte count, int size, Span<byte> dest)
        {
            Debug.Assert(dest.Length >= size);

            dest[0] = count;

            return dest.Slice(0, size);
        }
    }
}
