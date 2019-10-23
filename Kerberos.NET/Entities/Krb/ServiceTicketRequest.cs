using Kerberos.NET.Crypto;
using Kerberos.NET.Server;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public struct ServiceTicketRequest
    {
        public IKerberosPrincipal Principal { get; set; }

        public KerberosKey EncryptedPartKey { get; set; }

        public IKerberosPrincipal ServicePrincipal { get; set; }

        public KerberosKey ServicePrincipalKey { get; set; }

        public TicketFlags Flags { get; set; }

        public IEnumerable<KrbHostAddress> Addresses { get; set; }

        public string RealmName { get; set; }

        public DateTimeOffset Now { get; set; }

        public DateTimeOffset StartTime { get; set; }

        public DateTimeOffset EndTime { get; set; }

        public DateTimeOffset? RenewTill { get; set; }

        public int Nonce { get; set; }

        public bool IncludePac { get; set; }
    }
}
