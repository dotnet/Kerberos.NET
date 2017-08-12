using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public class AES128DecryptedData : AESDecryptedData
    {
        public AES128DecryptedData(KrbApReq token)
            : base(token)
        {
            decryptor = new AES128Decryptor();
        }

        private readonly AES128Decryptor decryptor;

        protected override KerberosEncryptor Decryptor { get { return decryptor; } }
    }
}
