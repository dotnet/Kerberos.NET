using Kerberos.NET.Entities;

namespace Kerberos.NET
{
    public struct RequestServiceTicket
    {
        public string ServicePrincipalName { get; set; }

        public ApOptions ApOptions { get; set; }

        public string S4uTarget { get; set; }

        public KrbTicket S4uTicket { get; set; }

        public KrbTicket UserToUserTicket { get; set; }

        public KdcOptions KdcOptions { get; set; }
    }
}
