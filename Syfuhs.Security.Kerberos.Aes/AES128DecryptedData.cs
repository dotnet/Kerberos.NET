using Syfuhs.Security.Kerberos.Crypto;
using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos.Aes
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
