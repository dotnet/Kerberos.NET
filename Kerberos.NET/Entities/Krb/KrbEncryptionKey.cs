using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncryptionKey
    {
        public KerberosKey AsKey()
        {
            return new KerberosKey(this.KeyValue.ToArray(), etype: this.EType);
        }
    }
}
