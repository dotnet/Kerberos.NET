using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public class Ticket
    {
        public Ticket Decode(Asn1Element element)
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
                        SName = new PrincipalName().Decode(node[0], Realm);
                        break;

                    case 3:
                        EncPart = new EncryptedData().Decode(node);
                        break;
                }
            }

            return this;
        }

        public int TicketVersionNumber;

        public string Realm;

        public PrincipalName SName;

        public EncryptedData EncPart;
    }
}
