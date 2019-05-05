using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public class EncKrbCredPart
    {
        public EncKrbCredPart Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        var tickets = new List<KrbCredInfo>();

                        var ticketContainer = node[0];

                        for (var t = 0; t < ticketContainer.Count; t++)
                        {
                            var ticket = ticketContainer[t];

                            tickets.Add(new KrbCredInfo().Decode(ticket[0]));
                        }

                        Tickets = tickets;
                        break;
                    case 1:
                        Nonce = node[0].AsInt();
                        break;
                    case 2:
                        Timestamp = node[0].AsDateTimeOffset();
                        break;
                    case 3:
                        Usec = node[0].AsLong();
                        break;
                    case 4:
                        break;
                    case 5:
                        break;
                }
            }

            return this;
        }

        public IEnumerable<KrbCredInfo> Tickets;

        public int Nonce;
        public DateTimeOffset Timestamp;
        public long Usec;

    }
}
