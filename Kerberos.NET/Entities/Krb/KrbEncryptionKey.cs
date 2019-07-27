using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncryptionKey
    {
        public KerberosKey AsKey()
        {
            return new KerberosKey(this);
        }

        public static KrbEncryptionKey Generate(EncryptionType type)
        {
            var crypto = CryptoService.CreateTransform(type);

            return new KrbEncryptionKey
            {
                EType = type,
                KeyValue = crypto.GenerateKey()
            };
        }
    }
}
