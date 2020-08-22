// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Crypto
{
#if WEAKCRYPTO
    public static class RC4
    {
        public static void Transform(
            ReadOnlySpan<byte> originalKey,
            ReadOnlySpan<byte> data,
            Span<byte> output
        )
        {
            if (output.Length < data.Length)
            {
                throw new InvalidOperationException($"Output {output.Length} cannot be smaller than input {data.Length}");
            }

            Span<byte> key = stackalloc byte[256];
            Span<byte> s = stackalloc byte[256];

            int i;

            // for i from 0 to 255
            //     Key[i]
            //     S[i] := i
            // endfor

            for (i = 0; i < 256; i++)
            {
                key[i] = originalKey[i % originalKey.Length];
                s[i] = (byte)i;
            }

            var j = 0;

            // j := 0
            // for i from 0 to 255
            //     j := (j + S[i] + key[i mod keylength]) mod 256
            //     swap values of S[i] and S[j]
            // endfor

            for (i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i]) % 256;

                var swap = s[i];
                s[i] = s[j];
                s[j] = swap;
            }

            // i := 0
            // j := 0
            // while GeneratingOutput:
            //     i := (i + 1) mod 256
            //     j := (j + S[i]) mod 256
            //     swap values of S[i] and S[j]
            //     K := S[(S[i] + S[j]) mod 256]
            //     output K
            // endwhile

            // E = data ^ k

            i = 0;
            j = 0;

            for (var counter = 0; counter < data.Length; counter++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;

                var swap = s[i];
                s[i] = s[j];
                s[j] = swap;

                var k = s[(s[i] + s[j]) % 256];

                var keyed = data[counter] ^ k;

                output[counter] = (byte)keyed;
            }
        }
    }
#endif
}