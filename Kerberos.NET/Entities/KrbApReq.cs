using Kerberos.NET.Crypto;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public sealed class KrbApReq
    {
        public const int ApplicationTag = 14;

        public KrbApReq Decode(Asn1Element childNode)
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
                        Ticket = new Ticket().Decode(node[0]);
                        break;

                    case 4:
                        Authenticator = new EncryptedData().Decode(node);
                        break;
                }
            }

            return this;
        }

        public int ProtocolVersionNumber;

        public MessageType MessageType;

        public APOptions APOptions;

        public Ticket Ticket;

        public EncryptedData Authenticator;
    }
}
