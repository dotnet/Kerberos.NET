using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

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
        private static readonly RandomNumberGenerator RNG = RandomNumberGenerator.Create();

        public abstract int ChecksumSize { get; }

        public abstract int BlockSize { get; }

        public abstract int KeySize { get; }

        public virtual ReadOnlyMemory<byte> GenerateKey()
        {
            return GenerateRandomBytes(KeySize);
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

        public virtual ReadOnlyMemory<byte> MakeChecksum(
            ReadOnlyMemory<byte> data,
            KerberosKey key,
            KeyUsage usage,
            KeyDerivationMode kdf,
            int hashSize)
        {
            throw new NotImplementedException();
        }

        public virtual ReadOnlyMemory<byte> MakeChecksum(ReadOnlyMemory<byte> key, ReadOnlySpan<byte> data, KeyUsage keyUsage)
        {
            throw new NotImplementedException();
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
