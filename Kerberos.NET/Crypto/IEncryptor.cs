using Kerberos.NET.Entities;

namespace Kerberos.NET.Crypto
{
    public interface IEncryptor
    {
        int BlockSize { get; }

        int KeyInputSize { get; }

        int KeySize { get; }

        void Encrypt(byte[] key, byte[] ki);

        void Encrypt(byte[] ke, byte[] iv, byte[] tmpEnc);

        void Decrypt(byte[] ke, byte[] iv, byte[] tmpEnc);

        byte[] String2Key(KerberosKey key);
    }
}