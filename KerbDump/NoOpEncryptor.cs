using Kerberos.NET.Crypto;

namespace KerbDump
{
    internal class NoOpEncryptor : IEncryptor
    {
        public int BlockSize => 0;

        public int KeyInputSize => 0;

        public int KeySize => 0;

        public void Decrypt(byte[] key, byte[] iv, byte[] tmpEnc)
        {
            // no op
        }

        public void Encrypt(byte[] key, byte[] ki)
        {
            // no op
        }

        public void Encrypt(byte[] key, byte[] iv, byte[] tmpEnc)
        {
            // no op
        }

        public byte[] String2Key(KerberosKey key)
        {
            return key.PasswordBytes;
        }
    }
}
