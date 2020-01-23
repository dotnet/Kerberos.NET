using Kerberos.NET.Crypto;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncryptedData
    {
        public T Decrypt<T>(KerberosKey key, KeyUsage usage, Func<ReadOnlyMemory<byte>, T> func)
        {
            var crypto = CryptoService.CreateTransform(this.EType);

            if (crypto == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {key.EncryptionType}");
            }

            var decrypted = crypto.Decrypt(this.Cipher, key, usage);

            return func(decrypted);
        }

        public static KrbEncryptedData Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
        {
            var crypto = CryptoService.CreateTransform(key.EncryptionType);

            if (crypto == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {key.EncryptionType}");
            }

            ReadOnlyMemory<byte> cipher = crypto.Encrypt(data, key, usage);

            return new KrbEncryptedData
            {
                Cipher = cipher,
                EType = key.EncryptionType,
                KeyVersionNumber = key.Version
            };
        }
    }
}
