using System;

namespace Kerberos.NET.Crypto
{
    public abstract class Hasher : IHasher
    {
        private readonly int blockSize;
        private readonly IDigest digest;
        
        protected Hasher(int blockSize, IDigest digest)
        {
            this.blockSize = blockSize;
            this.digest = digest;
        }

        public int BlockSize { get { return blockSize; } }

        public byte[] CalculateDigest()
        {
            var digest = new byte[this.digest.GetDigestSize()];

            this.digest.DoFinal(digest, 0);

            return digest;
        }

        public void Hash(byte[] data)
        {
            Hash(data, 0, data.Length);
        }

        public void Hash(byte[] data, int start, int len)
        {
            digest.BlockUpdate(data, 0, data.Length);
        }
    }
}