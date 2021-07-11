// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Kerberos.NET.Crypto.Pal
{
    public class SP800108CounterModeKdf : IKeyDerivationAlgorithm
    {
        /*
         * This is an implementation of SP800-108 KDF in Counter Mode
         * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf
         */

        public ReadOnlyMemory<byte> Derive(
            HashAlgorithmName algName,
            ReadOnlyMemory<byte> passwordBytes,
            ReadOnlyMemory<byte> salt,
            int k,
            int keySize
        )
        {
            // K1 = HMAC-SHA-256(key, 0x00000001 | label | 0x00 | k)
            // length(0x00000001 | 0x00 | k) = 9

            var inputLength = salt.Length + 9;

            using (var inputRented = CryptoPool.Rent<byte>(inputLength))
            {
                var input = inputRented.Memory.Slice(0, inputLength);

                input.Span[3] = 1; // 0x00000001

                salt.CopyTo(input.Slice(4)); // label

                IHmacAlgorithm hmac;

                if (algName == HashAlgorithmName.SHA256)
                {
                    hmac = CryptoPal.Platform.HmacSha256(passwordBytes);
                }
                else
                {
                    hmac = CryptoPal.Platform.HmacSha384(passwordBytes);
                }

                BinaryPrimitives.WriteInt32BigEndian(input.Span.Slice(input.Length - 4), k);

                return hmac.ComputeHash(input).Slice(0, keySize);
            }
        }
    }
}
