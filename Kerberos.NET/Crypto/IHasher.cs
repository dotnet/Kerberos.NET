namespace Kerberos.NET.Crypto
{
    public interface IHasher
    {
        int BlockSize { get; }

        byte[] CalculateDigest();

        void Hash(byte[] tmp);

        void Hash(byte[] data, int start, int len);
    }
}