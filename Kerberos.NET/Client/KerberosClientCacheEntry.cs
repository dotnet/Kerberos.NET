using Kerberos.NET.Entities;

namespace Kerberos.NET.Client
{
    public struct KerberosClientCacheEntry
    {
        public KrbEncryptionKey SessionKey;

        public KrbKdcRep KdcResponse;

        public int Nonce { get; set; }
    }
}
