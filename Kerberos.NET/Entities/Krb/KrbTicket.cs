
using Kerberos.NET.Asn1;
using System;

namespace Kerberos.NET.Entities
{
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
