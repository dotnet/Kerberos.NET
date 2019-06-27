using Kerberos.NET.Asn1;
using System;

namespace Kerberos.NET.Entities
{
    public class KrbCredInfo
    {
        /*
        KrbCredInfo     ::= SEQUENCE {
            key             [0] EncryptionKey,
            prealm          [1] Realm OPTIONAL,
            pname           [2] PrincipalName OPTIONAL,
            flags           [3] TicketFlags OPTIONAL,
            authtime        [4] KerberosTime OPTIONAL,
            starttime       [5] KerberosTime OPTIONAL,
            endtime         [6] KerberosTime OPTIONAL,
            renew-till      [7] KerberosTime OPTIONAL,
            srealm          [8] Realm OPTIONAL,
            sname           [9] PrincipalName OPTIONAL,
            caddr           [10] HostAddresses OPTIONAL
        }
        */
        public KrbCredInfo Decode(Asn1Element element)
        {
            for (var i = 0; i < element.Count; i++)
            {
                var node = element[i];

                switch (node.ContextSpecificTag)
                {
                    case 0:
                        Key = new EncryptionKey().Decode(node[0]);
                        break;
                    case 1:
                        PRealm = node[0].AsString();
                        break;
                    case 2:
                        PrincipalName = new PrincipalName().Decode(node[0], PRealm);
                        break;
                    case 3:
                        Flags = (TicketFlags)node[0].AsInt();
                        break;
                    case 4:
                        AuthTime = node[0].AsDateTimeOffset();
                        break;
                    case 5:
                        StartTime = node[0].AsDateTimeOffset();
                        break;
                    case 6:
                        EndTime = node[0].AsDateTimeOffset();
                        break;
                    case 7:
                        RenewTill = node[0].AsDateTimeOffset();
                        break;
                    case 8:
                        SRealm = node[0].AsString();
                        break;
                    case 9:
                        SName = new PrincipalName().Decode(node[0], SRealm);
                        break;
                    case 10:
                        CAddr = node[0].AsLong();
                        break;

                }
            }

            return this;
        }

        public EncryptionKey Key;
        public string PRealm;
        public PrincipalName PrincipalName;
        public TicketFlags Flags;
        public DateTimeOffset AuthTime;
        public DateTimeOffset StartTime;
        public DateTimeOffset EndTime;
        public DateTimeOffset RenewTill;
        public string SRealm;
        public PrincipalName SName;
        public long CAddr;
    }
}
