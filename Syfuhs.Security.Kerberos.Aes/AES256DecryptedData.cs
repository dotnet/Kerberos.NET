using Syfuhs.Security.Kerberos.Crypto;
using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos.Aes
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
