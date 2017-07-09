using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Syfuhs.Security.Kerberos.Crypto
{
    public abstract class Hasher : IHasher
    {
        private readonly int blockSize;
        private readonly string algorithm;

        private readonly IDigest hash;

        public int BlockSize { get { return blockSize; } }

        protected Hasher(int hashSize, int blockSize, string algorithm)
        {
            this.blockSize = blockSize;
            this.algorithm = algorithm;

            hash = DigestUtilities.GetDigest(algorithm);
        }

        public byte[] CalculateDigest()
        {
            var digest = new byte[hash.GetDigestSize()];

            hash.DoFinal(digest, 0);

            return digest;
        }

        public void Hash(byte[] data)
        {
            Hash(data, 0, data.Length);
        }

        public void Hash(byte[] data, int start, int len)
        {
            hash.BlockUpdate(data, 0, data.Length);
        }
    }
}