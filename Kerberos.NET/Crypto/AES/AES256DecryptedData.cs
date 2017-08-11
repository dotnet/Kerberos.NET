using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

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
