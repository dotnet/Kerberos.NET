using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public class Authenticator
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
                        CName = new PrincipalName(node[0], Realm);
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
                        SubSessionKey = new EncryptionKey(node[0]);
                        break;
                    case 7:
                        SequenceNumber = node[0].AsLong();
                        break;
                    case 8:
                        var parent = node[0];

                        for (var p = 0; p < parent.Count; p++)
                        {
                            var azElements = AuthorizationDataElement.ParseElements(parent[p]);
                            
                            Authorizations.AddRange(azElements);
                        }
                        break;
                }
            }
        }

        public long VersionNumber { get; }

        public string Realm { get; }

        public PrincipalName CName { get; }

        public byte[] Checksum { get; }

        public long CuSec { get; }

        public DateTimeOffset CTime { get; }

        [Obsolete]
        public byte[] Subkey { get { return SubSessionKey?.RawKey; } }

        public EncryptionKey SubSessionKey { get; }

        public long SequenceNumber { get; }

        private List<AuthorizationData> authorizations;

        public List<AuthorizationData> Authorizations { get { return authorizations ?? (authorizations = new List<AuthorizationData>()); } }

        public override string ToString()
        {
            return $"Version: {VersionNumber} | Realm: {Realm} | Sequence: {SequenceNumber}";
        }
    }
}
