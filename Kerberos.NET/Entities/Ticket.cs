using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class Ticket
    {
        public Ticket(Asn1Element element)
        {
            var childNode = element[0];

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        TicketVersionNumber = node[0].AsInt();
                        break;

                    case 1:
                        Realm = node[0].AsString();
                        break;

                    case 2:
                        SName = new PrincipalName(node[0], Realm);
                        break;

                    case 3:
                        EncPart = new EncryptedData(node);
                        break;
                }
            }
        }

        public int TicketVersionNumber { get; }

        public string Realm { get; }

        public PrincipalName SName { get; }

        public EncryptedData EncPart { get; }
    }
}
