using Syfuhs.Security.Kerberos.Crypto;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class Ticket : Asn1ValueType
    {
        public Ticket(Asn1Element element)
        {
            Asn1Element childNode = element[0][0];

            Asn1Value = childNode.Value;

            for (int i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        TicketVersionNumber = (int)node[0].AsLong();
                        break;

                    case 1:
                        Realm = node[0].AsString();
                        break;

                    case 2:
                        SName = new PrincipalName(node);
                        break;

                    case 3:
                        EncPart = new EncryptedData(node);
                        break;
                }
            }
        }

        public int TicketVersionNumber { get; private set; }

        public string Realm { get; private set; }

        public PrincipalName SName { get; private set; }

        public EncryptedData EncPart { get; private set; }
    }
}
