using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Server
{
    public class PreAuthenticationContext
    {
        public IKerberosPrincipal Principal { get; set; }

        public KerberosKey EncryptedPartKey { get; set; }

        public bool PreAuthenticationSatisfied => EncryptedPartKey != null;

        public IEnumerable<KrbPaData> PaData { get; set; }

        public KrbEncTicketPart Ticket { get; set; }

        public Exception Failure { get; set; }
    }
}
