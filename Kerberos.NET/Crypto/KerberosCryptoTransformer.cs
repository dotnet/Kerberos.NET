using Kerberos.NET.Entities;
using System.Runtime.CompilerServices;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosCryptoTransformer
    {
        public abstract int ChecksumSize { get; }

        public abstract byte[] Decrypt(byte[] cipher, KerberosKey key, KeyUsage usage);

        public abstract byte[] MakeChecksum(byte[] key, byte[] data, int hashSize, int keyUsage = 0);
        
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