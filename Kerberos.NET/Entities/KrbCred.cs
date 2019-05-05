using Kerberos.NET.Crypto;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public class KrbCred
    {
        public KrbCred Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        ProtocolVersion = node[0].AsInt();
                        break;
                    case 1:
                        MessageType = (MessageType)node[0].AsInt();
                        break;
                    case 2:
                        var tickets = new List<Ticket>();

                        var sequenceContainer = node[0];

                        for (var t = 0; t < sequenceContainer.Count; t++)
                        {
                            var sequence = sequenceContainer[t];

                            tickets.Add(new Ticket().Decode(sequence));
                        }

                        Tickets = tickets;
                        break;
                    case 3:
                        EncryptedData = new EncryptedData().Decode(node);
                        break;
                }
            }

            return this;
        }

        public int ProtocolVersion;
        public MessageType MessageType;
        public IEnumerable<Ticket> Tickets;
        public EncryptedData EncryptedData;

        public EncKrbCredPart CredentialPart;
    }
}
