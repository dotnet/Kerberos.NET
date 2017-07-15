using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos.Entities
{
    [Flags]
    public enum TicketFlags : long
    {
        None = -1,
        Forwardable = 0x40000000,
        Forwarded = 0x20000000,
        Proxiable = 0x10000000,
        Proxy = 0x08000000,
        MayPostDate = 0x04000000,
        PostDated = 0x02000000,
        Invalid = 0x01000000,
        Renewable = 0x00800000,
        Initial = 0x00400000,
        PreAuthenticated = 0x00200000,
        HardwareAuthentication = 0x00100000,
        TransitPolicyChecked = 0x00080000,
        OkAsDelegate = 0x00040000,
        EncryptedPreAuthentication = 0x00010000,
        Anonymous = 0x00008000
    }

    public class EncTicketPart
    {
        public EncTicketPart(Asn1Element asn1Element)
        {
            var childNode = asn1Element[0];

            if (childNode == null)
            {
                return;
            }

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        TicketFlags = (TicketFlags)node[0].AsLong();
                        break;
                    case 1:
                        EncryptionKey = node[0][1][0].Value;
                        break;
                    case 2:
                        CRealm = node[0].AsString();
                        break;
                    case 3:
                        CName = new PrincipalName(node, CRealm);
                        break;
                    case 4:
                        for (int l = 0; l < node.Count; l++)
                        {
                            var t = new Asn1Element(node.Value);
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
                        HostAddresses = node[0].AsLong();
                        break;
                    case 10:

                        var parent = node[0];

                        AuthorizationData = new AuthorizationData(parent);

                        break;
                }
            }
        }

        public TicketFlags TicketFlags { get; private set; }

        public byte[] EncryptionKey { get; private set; }

        public string CRealm { get; private set; }

        public PrincipalName CName { get; private set; }

        private List<TransitedEncoding> transited;

        public List<TransitedEncoding> Transited { get { return transited ?? (transited = new List<TransitedEncoding>()); } }

        public DateTimeOffset AuthTime { get; private set; }

        public DateTimeOffset StartTime { get; private set; }

        public DateTimeOffset EndTime { get; private set; }

        public DateTimeOffset RenewTill { get; private set; }

        public long HostAddresses { get; private set; }

        public AuthorizationData AuthorizationData { get; private set; }

        public override string ToString()
        {
            var cname = string.Join(",", CName.Names);

            return $"Flags: {TicketFlags} | CName: {CName.NameType}, {cname} | CRealm: {CRealm};";
        }
    }
}
