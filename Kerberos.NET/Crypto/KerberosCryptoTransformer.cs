using Kerberos.NET.Entities;
using System;
using System.Runtime.CompilerServices;

namespace Kerberos.NET.Crypto
{
    public enum KeyDerivationMode : byte
    {
        Kc = 0x99,
        Ke = 0xAA,
        Ki = 0x55
    }

    public abstract class KerberosCryptoTransformer
    {
        public abstract int ChecksumSize { get; }

        public abstract int BlockSize { get; }

        public abstract int KeySize { get; }

        public abstract byte[] String2Key(KerberosKey key);

        public abstract byte[] Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey key, KeyUsage usage);

        public virtual byte[] MakeChecksum(byte[] key, KeyUsage usage, KeyDerivationMode kdf, byte[] data, int hashSize)
        {
            throw new NotImplementedException();
        }

        public virtual byte[] MakeChecksum(byte[] key, byte[] data, KeyUsage keyUsage)
        {
            throw new NotImplementedException();
        }

        protected virtual byte[] Random2Key(byte[] randomBits)
        {
            return randomBits;
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool AreEqualSlow(byte[] left, byte[] right, int rightLength = 0)
        {
            if (rightLength <= 0)
            {
                rightLength = right.Length;
            }

            var diff = left.Length ^ rightLength;

            for (var i = 0; i < left.Length; i++)
            {
                diff |= (left[i] ^ right[i]);
            }

            return diff == 0;
        }
    }
}