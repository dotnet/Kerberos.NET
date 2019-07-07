using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncryptedData
    {
        public T Decrypt<T>(Func<ReadOnlyMemory<byte>, T> func, KerberosKey key, KeyUsage usage)
        {
            var crypto = CryptographyService.CreateTransform(this.EType);

            var decrypted = crypto.Decrypt(this.Cipher, key, usage);

            return func(decrypted);
        }

        public static KrbEncryptedData Encrypt(ReadOnlySpan<byte> data, KerberosKey key, EncryptionType etype, KeyUsage usage)
        {
            var crypto = CryptographyService.CreateTransform(etype);

            ReadOnlyMemory<byte> cipher = crypto.Encrypt(data, key, usage);

            return new KrbEncryptedData
            {
                Cipher = cipher,
                EType = etype,
                KeyVersionNumber = key.Version
            };
        }
    }
}
