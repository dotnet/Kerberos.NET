using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos.Aes
{
    public static class AESKerberosConfiguration
    {
        public static void Register()
        {
            KerberosRequest.RegisterDecryptor(
               EncryptionType.AES128_CTS_HMAC_SHA1_96,
               (token, key) => new AES128DecryptedData(token, key)
           );

            KerberosRequest.RegisterDecryptor(
                EncryptionType.AES256_CTS_HMAC_SHA1_96,
                (token, key) => new AES256DecryptedData(token, key)
            );
        }
    }
}
