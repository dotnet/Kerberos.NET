// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosCryptoTransformer
    {
        private static readonly RandomNumberGenerator RNG = RandomNumberGenerator.Create();
        protected static readonly ReadOnlyMemory<byte> PrfConstant = UnicodeStringToUtf8("prf");

        public abstract int ChecksumSize { get; }

        public abstract int BlockSize { get; }

        public abstract int KeySize { get; }

        public abstract ChecksumType ChecksumType { get; }

        public abstract EncryptionType EncryptionType { get; }

        public virtual ReadOnlyMemory<byte> GenerateKey()
        {
            return this.GenerateRandomBytes(this.KeySize);
        }

        public abstract ReadOnlyMemory<byte> String2Key(KerberosKey key);

        public abstract ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey key, KeyUsage usage);

        public abstract ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage);

        public virtual ReadOnlyMemory<byte> GenerateRandomBytes(int size)
        {
            var arr = new byte[size];

            RNG.GetBytes(arr);

            return new ReadOnlyMemory<byte>(arr);
        }

        public virtual ReadOnlyMemory<byte> Random2Key(ReadOnlyMemory<byte> random)
        {
            return random;
        }

        public virtual ReadOnlyMemory<byte> MakeChecksum(
            ReadOnlyMemory<byte> data,
            KerberosKey key,
            KeyUsage usage,
            KeyDerivationMode kdf,
            int hashSize)
        {
            throw new NotSupportedException();
        }

        public virtual ReadOnlyMemory<byte> MakeChecksum(ReadOnlyMemory<byte> key, ReadOnlySpan<byte> data, KeyUsage keyUsage)
        {
            throw new NotSupportedException();
        }

        public virtual ReadOnlyMemory<byte> PseudoRandomFunction(ReadOnlyMemory<byte> key, ReadOnlyMemory<byte> input)
        {
            throw new NotSupportedException();
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool AreEqualSlow(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            var diff = left.Length ^ right.Length;

            for (var i = 0; i < left.Length; i++)
            {
                diff |= (left[i] ^ right[i]);
            }

            return diff == 0;
        }
    }
}
