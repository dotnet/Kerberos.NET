using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos.Aes
{
    public static class AESKerberosConfiguration
    {
        public static void Register()
        {
            KerberosRequest.RegisterDecryptor(
               EncryptionType.AES128_CTS_HMAC_SHA1_96,
               (token) => new AES128DecryptedData(token)
           );

            KerberosRequest.RegisterDecryptor(
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                (token) => new AES256DecryptedData(token)
            );
        }
    }
}
