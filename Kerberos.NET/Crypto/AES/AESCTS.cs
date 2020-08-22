// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    internal static class AESCTS
    {
        private const int BlockSize = 16;
        private const int TwoBlockSizes = BlockSize * 2;

        public static ReadOnlyMemory<byte> Encrypt(
            ReadOnlyMemory<byte> plainText,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> iv
        )
        {
            if (!CalculateLength(plainText.Length, out int padSize, out int maxLength))
            {
                return plainText;
            }

            using (var rental = CryptoPool.Rent<byte>(maxLength))
            {
                Memory<byte> plaintextRented;

                if (padSize == BlockSize)
                {
                    plaintextRented = rental.Memory.Slice(0, plainText.Length);
                    plainText.CopyTo(plaintextRented);
                }
                else
                {
                    plaintextRented = rental.Memory.Slice(0, maxLength);
                    plainText.CopyTo(plaintextRented);

                    plaintextRented.Span.Slice(plaintextRented.Length - padSize).Fill(0);
                }

                var aes = CryptoPal.Platform.Aes();

                var encrypted = aes.Encrypt(plaintextRented, key, iv);

                if (plainText.Length >= TwoBlockSizes)
                {
                    SwapLastTwoBlocks(encrypted.Span);
                }

                return encrypted.Slice(0, plainText.Length);
            }
        }

        public static ReadOnlyMemory<byte> Decrypt(
            ReadOnlyMemory<byte> ciphertext,
            ReadOnlyMemory<byte> key,
            ReadOnlyMemory<byte> iv
        )
        {
            if (!CalculateLength(ciphertext.Length, out int padSize, out int maxLength))
            {
                return ciphertext;
            }

            using (var rental = CryptoPool.Rent<byte>(maxLength))
            {
                var aes = CryptoPal.Platform.Aes();

                Memory<byte> ciphertextRented;

                if (padSize == BlockSize)
                {
                    ciphertextRented = rental.Memory.Slice(0, ciphertext.Length);

                    ciphertext.CopyTo(ciphertextRented);
                }
                else
                {
                    var depadded = Depad(ciphertext, padSize);

                    var decryptedPad = aes.Decrypt(depadded, key, iv);

                    ciphertextRented = rental.Memory.Slice(0, maxLength);

                    ciphertext.CopyTo(ciphertextRented);

                    decryptedPad.Slice(decryptedPad.Length - padSize)
                                .CopyTo(
                                    ciphertextRented.Slice(ciphertext.Length)
                                );
                }

                if (ciphertext.Length >= TwoBlockSizes)
                {
                    SwapLastTwoBlocks(ciphertextRented.Span);
                }

                return aes.Decrypt(ciphertextRented, key, iv).Slice(0, ciphertext.Length);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool CalculateLength(int len, out int padSize, out int maxLength)
        {
            padSize = BlockSize - (len % BlockSize);

            maxLength = len + padSize;

            return len >= BlockSize;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ReadOnlyMemory<byte> Depad(ReadOnlyMemory<byte> ciphertext, int padSize)
        {
            var offset = ciphertext.Length - TwoBlockSizes + padSize;

            return ciphertext.Slice(offset, BlockSize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void SwapLastTwoBlocks(Span<byte> data)
        {
            var blockOne = data.Length - TwoBlockSizes;
            var blockTwo = data.Length - BlockSize;

            for (var i = 0; i < BlockSize; i++)
            {
                var temp = data[i + blockOne];

                data[i + blockOne] = data[i + blockTwo];
                data[i + blockTwo] = temp;
            }
        }
    }
}