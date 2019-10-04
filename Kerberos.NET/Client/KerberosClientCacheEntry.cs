using Kerberos.NET.Entities;

namespace Kerberos.NET.Client
{
    public struct KerberosClientCacheEntry
    {
        public KrbEncryptionKey SessionKey;

        public KrbKdcRep Ticket;
    }
}
