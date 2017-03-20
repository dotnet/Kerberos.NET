using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class EncTicketPart : Asn1ValueType
    {
        public EncTicketPart(Asn1Element asn1Element)
        {
            var childNode = asn1Element[0];

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        TicketFlags = node[0].AsLong();
                        break;
                    case 1:
                        EncryptionKey = node[0][1][0].Value;
                        break;
                    case 2:
                        CRealm = node[0].AsString();
                        break;
                    case 3:
                        CName = new PrincipalName(node);
                        break;
                    case 4:
                        for (int l = 0; l < node.Count; l++)
                        {
                            var t = node[l];
                            Transited.Add(new TransitedEncoding(t));
                        }
                        break;
                    case 5:
                        AuthTime = node[0].AsDateTimeOffset();
                        break;
                    case 6:
                        StartTime = node[0].AsDateTimeOffset();
                        break;
                    case 7:
                        EndTime = node[0].AsDateTimeOffset();
                        break;
                    case 8:
                        RenewTill = node[0].AsDateTimeOffset();
                        break;
                    case 9:
                        HostAddress = node[0].AsLong();
                        break;
                    case 10:

                        var parent = node[0];

                        AuthorizationData = new AuthorizationData(parent);

                        break;
                }
            }
        }

        public long TicketFlags { get; private set; }

        public byte[] EncryptionKey { get; private set; }

        public string CRealm { get; private set; }

        public PrincipalName CName { get; private set; }

        private List<TransitedEncoding> transited;

        public List<TransitedEncoding> Transited { get { return transited ?? (transited = new List<TransitedEncoding>()); } }

        public DateTimeOffset AuthTime { get; private set; }

        public DateTimeOffset StartTime { get; private set; }

        public DateTimeOffset EndTime { get; private set; }

        public DateTimeOffset RenewTill { get; private set; }

        public long HostAddress { get; private set; }

        public AuthorizationData AuthorizationData { get; private set; }

        public override string ToString()
        {

            return $"Flags: {TicketFlags} | CName: {CName.NameType}, {cname} | CRealm: {CRealm};";
        }
    }
}
