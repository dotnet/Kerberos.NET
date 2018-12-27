using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities
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

    public class EncryptionKey
    {
        public EncryptionKey Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        KeyType = (EncryptionType)node[0].AsInt();
                        break;
                    case 1:
                        RawKey = node[0].Value;
                        break;
                }
            }

            return this;
        }

        public EncryptionType KeyType;

        public byte[] RawKey;
    }

    public class EncTicketPart
    {
        public EncTicketPart Decode(Asn1Element asn1Element)
        {
            var childNode = asn1Element[0];

            if (childNode == null)
            {
                return null;
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
                        Key = new EncryptionKey().Decode(node[0]);
                        break;
                    case 2:
                        CRealm = node[0].AsString();
                        break;
                    case 3:
                        CName = new PrincipalName().Decode(node[0], CRealm);
                        break;
                    case 4:
                        for (int l = 0; l < node.Count; l++)
                        {
                            Transited.Add(new TransitedEncoding().Decode(node[l]));
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

                        var authorizations = new List<AuthorizationData>();

                        for (var p = 0; p < parent.Count; p++)
                        {
                            var azElements = AuthorizationDataElement.ParseElements(parent[p]);

                            authorizations.AddRange(azElements);
                        }

                        AuthorizationData = authorizations;
                        break;
                }
            }

            return this;
        }

        public TicketFlags TicketFlags;

        [Obsolete]
        public byte[] EncryptionKey { get { return Key?.RawKey; } }

        public EncryptionKey Key;

        public string CRealm;

        public PrincipalName CName;

        private List<TransitedEncoding> transited;

        public List<TransitedEncoding> Transited { get { return transited ?? (transited = new List<TransitedEncoding>()); } }

        public DateTimeOffset AuthTime;

        public DateTimeOffset StartTime;

        public DateTimeOffset EndTime;

        public DateTimeOffset RenewTill;

        public long HostAddresses;

        public IEnumerable<AuthorizationData> AuthorizationData;

        public override string ToString()
        {
            var cname = string.Join(",", CName.Names);

            return $"Flags: {TicketFlags} | CName: {CName.NameType}, {cname} | CRealm: {CRealm};";
        }
    }
}
