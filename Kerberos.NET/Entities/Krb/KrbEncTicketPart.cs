
using Kerberos.NET.Asn1;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncTicketPart : IAsn1ApplicationEncoder<KrbEncTicketPart>
    {
        public KrbEncTicketPart DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return DecodeApplication(data);
        }
    }
}
