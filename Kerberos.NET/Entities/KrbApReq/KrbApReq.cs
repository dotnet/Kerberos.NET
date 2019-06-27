using System.Runtime.InteropServices;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public enum APOptions : uint
    {
        // X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X
        // 1 0 0
        // 0 1 0
        // 0 0 1
        RESERVED = 0,
        CHANNEL_BINDING_SUPPORTED = 1 << 14,
        USE_SESSION_KEY = 1 << 30,
        MUTUAL_REQUIRED = 1 << 29
    }

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
