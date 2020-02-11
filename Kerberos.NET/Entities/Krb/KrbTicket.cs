
using Kerberos.NET.Asn1;
using System;
using System.Diagnostics;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{SName} @ {Realm}")]
    public partial class KrbTicket : IAsn1ApplicationEncoder<KrbTicket>
    {
        public KrbTicket DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return Decode(ApplicationTag, data);
        }

        public KrbTicket()
        {
            TicketNumber = 5;
        }
    }
}
