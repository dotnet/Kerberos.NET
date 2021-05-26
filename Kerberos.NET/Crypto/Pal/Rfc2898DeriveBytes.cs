// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using static Kerberos.NET.BinaryExtensions;
using Rfc2898DeriveBytesAlgorithm = System.Security.Cryptography.Rfc2898DeriveBytes;

namespace Kerberos.NET.Crypto
{
    public class Rfc2898DeriveBytes : IKeyDerivationAlgorithm
    {
        private static readonly ConstructorInfo rfc2898Ctor;

        public static bool AttemptReflectionLookup { get; set; } = true;

        static Rfc2898DeriveBytes()
        {
            var type = typeof(Rfc2898DeriveBytesAlgorithm);

            rfc2898Ctor = type.GetConstructor(new[]
            {
                typeof(byte[]),
                typeof(byte[]),
                typeof(int),
                typeof(HashAlgorithmName)
            });
        }

        public ReadOnlyMemory<byte> Derive(
            HashAlgorithmName algName,
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int iterations,
            int keySize
        )
        {
            var passwordArray = TryGetArrayFast(passwordBytes);
            var saltArray = TryGetArrayFast(salt);

            if (algName == HashAlgorithmName.SHA256)
            {
                return this.DeriveSha256(passwordArray, salt, iterations, keySize);
            }

            if (algName == HashAlgorithmName.SHA384)
            {
                return this.DeriveSha384(passwordArray, salt, iterations, keySize);
            }

            using (var derive = new Rfc2898DeriveBytesAlgorithm(passwordArray, saltArray, iterations))
            {
                return derive.GetBytes(keySize);
            }
        }

        private ReadOnlyMemory<byte> DeriveSha256(byte[] passwordBytes, ReadOnlyMemory<byte> salt, int iterations, int keySize)
        {
            Rfc2898DeriveBytesAlgorithm algo = TryGetAlgorithm(passwordBytes, salt, iterations, HashAlgorithmName.SHA256);

            if (algo != null)
            {
                return algo.GetBytes(keySize);
            }

            using (var hmac = CryptoPal.Platform.HmacSha256(passwordBytes))
            {
                return DeriveManually(salt, iterations, keySize, hmac);
            }
        }

        private static Rfc2898DeriveBytesAlgorithm TryGetAlgorithm(byte[] passwordBytes, ReadOnlyMemory<byte> salt, int iterations, HashAlgorithmName hash)
        {
            // .NET Standard 2.0 doesn't contain this particular ctor overload
            // so we're going to see if it exists and use it instead

            if (!AttemptReflectionLookup || rfc2898Ctor == null)
            {
                return null;
            }

            var algo = rfc2898Ctor.Invoke(new object[] { passwordBytes, salt.ToArray(), iterations, hash });

            return algo as Rfc2898DeriveBytesAlgorithm;
        }

        private ReadOnlyMemory<byte> DeriveSha384(byte[] passwordBytes, ReadOnlyMemory<byte> salt, int iterations, int keySize)
        {
            Rfc2898DeriveBytesAlgorithm algo = TryGetAlgorithm(passwordBytes, salt, iterations, HashAlgorithmName.SHA384);

            if (algo != null)
            {
                return algo.GetBytes(keySize);
            }

            using (var hmac = CryptoPal.Platform.HmacSha384(passwordBytes))
            {
                return DeriveManually(salt, iterations, keySize, hmac);
            }
        }

        private static ReadOnlyMemory<byte> DeriveManually(ReadOnlyMemory<byte> salt, int iterations, int keySize, IHmacAlgorithm hmac)
        {
            // This is here because .NET Standard doesn't include the built-in
            // ctor so it's possible the particular framework doesn't support it.
            // It's mostly based off the original Rfc2898DeriveBytes implementation.

            var key = new byte[salt.Length + 4];

            salt.Span.CopyTo(key);

            var hashSize = hmac.HashSize / 8;

            using (var buffer = CryptoPool.Rent<byte>(hashSize * iterations))
            {
                for (int i = 0; i < hashSize; i++)
                {
                    BinaryPrimitives.WriteInt32BigEndian(key.AsSpan().Slice(salt.Length), i + 1);

                    var temp = MemoryMarshal.AsMemory(hmac.ComputeHash(key));
                    key.AsSpan().Slice(salt.Length, 4).Fill(0);

                    var ret = temp;

                    for (int j = 1; j < iterations; j++)
                    {
                        temp = MemoryMarshal.AsMemory(hmac.ComputeHash(temp));

                        for (int k = 0; k < ret.Length; k++)
                        {
                            ret.Span[k] ^= temp.Span[k];
                        }
                    }

                    ret.CopyTo(buffer.Memory.Slice(hashSize * i));
                }

                var final = new byte[keySize];

                buffer.Memory.Slice(0, keySize).CopyTo(final);

                return final;
            }
        }
    }
}
