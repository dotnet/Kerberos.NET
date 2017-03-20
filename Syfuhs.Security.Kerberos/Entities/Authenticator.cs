using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class Authenticator : Asn1ValueType
    {
        public Authenticator(Asn1Element asn1Element)
        {
            Asn1Element childNode = asn1Element[0];

            for (var i = 0; i < childNode.Count; i++)
            {
                var node = childNode[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        VersionNumber = node[0].AsLong();
                        break;
                    case 1:
                        Realm = node[0].AsString();
                        break;
                    case 2:
                        CName = new PrincipalName(node);
                        break;
                    case 3:
                        Checksum = node[0].Value;
                        break;
                    case 4:
                        CuSec = node[0].AsLong();
                        break;
                    case 5:
                        CTime = node[0].AsDateTimeOffset();
                        break;
                    case 6:
                        Subkey = node[0][1][0].Value;
                        break;
                    case 7:
                        SequenceNumber = node[0].AsLong();
                        break;
                    case 8: // this is not right. its ASN.1 plus vendor-specific data
                        var parent = node[0];

                        for (var p = 0; p < parent.Count; p++)
                        {
                            var child = parent[p];

                            Authorizations.Add(new AuthorizationData(parent));
                        }
                        break;
                }
            }
        }

        public long VersionNumber { get; private set; }

        public string Realm { get; private set; }

        public PrincipalName CName { get; private set; }

        public byte[] Checksum { get; private set; }

        public long CuSec { get; private set; }

        public DateTimeOffset CTime { get; private set; }

        public byte[] Subkey { get; private set; }

        public long SequenceNumber { get; private set; }

        private List<AuthorizationData> authorizations;

        public List<AuthorizationData> Authorizations { get { return authorizations ?? (authorizations = new List<AuthorizationData>()); } }

        public override string ToString()
        {
            return $"Version: {VersionNumber} | Realm: {Realm} | Sequence: {SequenceNumber}";
        }
    }
}
