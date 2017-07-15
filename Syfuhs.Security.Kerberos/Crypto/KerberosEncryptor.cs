using Syfuhs.Security.Kerberos.Entities;
using System;

namespace Syfuhs.Security.Kerberos.Crypto
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

        public virtual int PaddingSize { get { return 0; } }

        public virtual byte[] Decrypt(KrbApReq token, KerberosKey key, KeyUsage usage)
        {
            return Decrypt(token.Ticket.EncPart.Cipher, key.WithPrincipalName(token.Ticket.SName), usage);
        }

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