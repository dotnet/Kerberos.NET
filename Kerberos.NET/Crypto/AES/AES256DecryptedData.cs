using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto.AES
{
    public class AES256DecryptedData : AESDecryptedData
    {
        public AES256DecryptedData(KrbApReq token)
            : base(token)
        {
            decryptor = new AES256Decryptor();
        }

        private readonly AES256Decryptor decryptor;

        protected override KerberosEncryptor Decryptor { get { return decryptor; } }
    }
}
