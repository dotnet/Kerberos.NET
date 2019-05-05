using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public class RC4DecryptedData : DecryptedData
    {
        private static readonly MD4Encryptor MD4Encryptor = new MD4Encryptor();

        public RC4DecryptedData(KrbApReq token)
            : base(token, new RC4Transformer(MD4Encryptor))
        {
        }
    }

    internal class MD4Encryptor : IEncryptor
    {
        public int BlockSize { get { throw new NotSupportedException(); } }

        public int KeyInputSize { get { throw new NotSupportedException(); } }

        public int KeySize { get { throw new NotSupportedException(); } }

        public void Decrypt(byte[] ke, byte[] iv, byte[] tmpEnc)
        {
            throw new NotSupportedException();
        }

        public void Encrypt(byte[] key, byte[] ki)
        {
            throw new NotSupportedException();
        }

        public void Encrypt(byte[] ke, byte[] iv, byte[] tmpEnc)
        {
            throw new NotSupportedException();
        }

        public byte[] String2Key(KerberosKey key)
        {
            return MD4(key.PasswordBytes);
        }

        private static byte[] MD4(byte[] key)
        {
            return new MD4().ComputeHash(key);
        }
    }
}
