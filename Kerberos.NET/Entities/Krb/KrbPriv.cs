using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbPriv
    {
        public static KrbPriv Create(KerberosKey key, KrbEncKrbPrivPart krbPrivEncPartUnencrypted)
        {
            return new KrbPriv
            {
                ProtocolVersionNumber = 5,
                MessageType = MessageType.KRB_PRIV,
                EncryptedPart = KrbEncryptedData.Encrypt(
                            data: krbPrivEncPartUnencrypted.EncodeApplication(),
                            key: key,
                            usage: KeyUsage.EncKrbPrivPart)
            };
        }
    }
}
