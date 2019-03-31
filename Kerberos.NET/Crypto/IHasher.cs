namespace Kerberos.NET.Crypto
{
    public interface IHasher
    {
        byte[] Hmac(byte[] key, byte[] data);
    }
}