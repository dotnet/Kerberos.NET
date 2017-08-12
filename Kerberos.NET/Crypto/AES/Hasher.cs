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
            var hashedDigest = new byte[digest.GetDigestSize()];

            digest.DoFinal(hashedDigest, 0);

            return hashedDigest;
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