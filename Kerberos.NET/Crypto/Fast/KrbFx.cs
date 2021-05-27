// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using static System.FormattableString;

namespace Kerberos.NET.Crypto
{
    public static class KrbFx
    {
        /// <summary>
        /// KRB-FX-CF1: Concatenate two strings into a single string.
        /// KRB-FX-CF1(UTF-8 string, UTF-8 string) -> (UTF-8 string)
        /// KRB-FX-CF1(x, y) := x || y
        /// </summary>
        /// <param name="x">The first string</param>
        /// <param name="y">The second string</param>
        /// <returns>Returns the two strings concatenated</returns>
        public static string Cf1(string x, string y)
        {
            return Invariant($"{x}{y}");
        }

        /// <summary>
        /// KRB-FX-CF1: Concatenate two strings into a single string.
        /// KRB-FX-CF1(UTF-8 string, UTF-8 string) -> (UTF-8 string)
        /// KRB-FX-CF1(x, y) := x || y
        /// </summary>
        /// <param name="x">The first string</param>
        /// <param name="y">The second string</param>
        /// <returns>Returns the two strings concatenated</returns>
        public static ReadOnlyMemory<byte> Cf1(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y)
        {
            Memory<byte> result = new byte[x.Length + y.Length];

            x.CopyTo(result);
            y.CopyTo(result.Slice(x.Length));

            return result;
        }

        /// <summary>
        /// Combine a weak key with a strong key to produce a key of relative strength.
        /// KRB-FX-CF2(protocol key, protocol key, octet string, octet string)  ->  (protocol key)
        ///
        /// PRF+(K1, pepper1) -> octet-string-1
        /// PRF+(K2, pepper2) -> octet-string-2
        /// KRB-FX-CF2(K1, K2, pepper1, pepper2) := random-to-key(octet-string-1 ^ octet-string-2)
        /// </summary>
        /// <param name="key1">The first key</param>
        /// <param name="key2">The second key</param>
        /// <param name="pepper1">The first pepper</param>
        /// <param name="pepper2">The second pepper</param>
        /// <param name="type">The encryption type to determine which random2key function to use</param>
        /// <returns>Returns result of passing two strings through a PRF and XOR'ing the result.</returns>
        public static ReadOnlyMemory<byte> Cf2(
            ReadOnlyMemory<byte> key1,
            ReadOnlyMemory<byte> key2,
            ReadOnlyMemory<byte> pepper1,
            ReadOnlyMemory<byte> pepper2,
            EncryptionType type
        )
        {
            var handler = CryptoService.CreateTransform(type);

            var x = PseudoRandomPlus(key1, pepper1, handler);
            var y = PseudoRandomPlus(key2, pepper2, handler);

            for (var i = 0; i < handler.KeySize; i++)
            {
                x.Span[i] ^= y.Span[i];
            }

            return handler.Random2Key(x);
        }

        /// <summary>
        /// PRF+(protocol key, octet string) -> (octet string)
        /// PRF+(key, shared-info) := pseudo-random(key,  1 || shared-info ) ||
        ///          pseudo-random(key, 2 || shared-info ) ||
        ///          pseudo-random(key, 3 || shared-info ) || ...
        /// </summary>
        /// <param name="key">The key to run through the PRF</param>
        /// <param name="pepper">The pepper for the PRF</param>
        /// <param name="etype">The EncryptionType handler to execute the PRF</param>
        /// <returns>Returns the result of executing n rounds of the <see cref="KerberosCryptoTransformer" /> PRF.</returns>
        public static ReadOnlyMemory<byte> PseudoRandomPlus(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> pepper, EncryptionType etype)
        {
            var handler = CryptoService.CreateTransform(etype);

            return PseudoRandomPlus(key, pepper, handler);
        }

        private static Memory<byte> PseudoRandomPlus(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> pepper, KerberosCryptoTransformer handler)
        {
            // PRF+(protocol key, octet string) -> (octet string)
            // PRF+(key, shared-info) := pseudo-random(key,  1 || shared-info ) ||
            //          pseudo-random(key, 2 || shared-info ) ||
            //          pseudo-random(key, 3 || shared-info ) || ...

            using (var pool = CryptoPool.Rent<byte>(pepper.Length + 1))
            {
                Memory<byte> input = pool.Memory.Slice(0, pepper.Length + 1);

                int prfSize = handler.BlockSize;

                int iterations = handler.KeySize / prfSize;

                if (handler.KeySize % prfSize > 0)
                {
                    iterations++;
                }

                input.Span[0] = 1;

                pepper.CopyTo(input.Slice(1));

                Memory<byte> result = new byte[prfSize * iterations];

                for (var i = 0; i < iterations; i++)
                {
                    handler.PseudoRandomFunction(key, input)
                           .Slice(0, prfSize)
                           .CopyTo(result.Slice(i * prfSize));

                    input.Span[0]++;
                }

                return result;
            }
        }
    }
}
