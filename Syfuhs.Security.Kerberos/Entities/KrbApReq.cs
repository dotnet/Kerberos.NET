using Syfuhs.Security.Kerberos.Crypto;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class KrbApReq
    {
        public KrbApReq(Asn1Element childNode)
        {
            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        ProtocolVersionNumber = node[0].AsInt();
                        break;

                    case 1:
                        MessageType = (MessageType)node[0].AsLong();
                        break;

                    case 2:
                        APOptions = (APOptions)node[0].AsLong();
                        break;

                    case 3:
                        Ticket = new Ticket(node);
                        break;

                    case 4:
                        Authenticator = new EncryptedData(node);
                        break;
                }
            }
        }

        public int ProtocolVersionNumber { get; private set; }

        public MessageType MessageType { get; private set; }

        public APOptions APOptions { get; private set; }

        public Ticket Ticket { get; private set; }

        public EncryptedData Authenticator { get; private set; }
    }
}
