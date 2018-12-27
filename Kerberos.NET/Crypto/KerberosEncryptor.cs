using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public abstract class KerberosEncryptor
    {
        protected KerberosEncryptor(IEncryptor encryptor, IHasher hasher)
        {
            this.encryptor = encryptor;
            this.hasher = hasher;
        }

        public abstract int ChecksumSize { get; }

        private readonly IEncryptor encryptor;
        private readonly IHasher hasher;

        protected IEncryptor Encryptor { get { return encryptor; } }
        
        public abstract byte[] Decrypt(byte[] cipher, KerberosKey key, KeyUsage usage);

        protected virtual byte[] MakeChecksum(byte[] key, byte[] data, int hashSize)
        {
            var hash = KerberosHash.KerberosHMAC(hasher, key, data);

            var output = new byte[hashSize];

            Buffer.BlockCopy(hash, 0, output, 0, hashSize);

            return output;
        }

        public static bool SlowCompare(byte[] left, byte[] right)
        {
            var diff = left.Length ^ right.Length;

            for (var i = 0; i < left.Length && i < right.Length; i++)
            {
                diff |= (left[i] ^ right[i]);
            }

            return diff == 0;
        }
    }
}