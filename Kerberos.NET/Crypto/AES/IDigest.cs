namespace Kerberos.NET.Crypto
{
    public interface IDigest
    {
        void BlockUpdate(byte[] input, int inOff, int length);

        int DoFinal(byte[] output, int outOff);

        int GetDigestSize();
    }
}