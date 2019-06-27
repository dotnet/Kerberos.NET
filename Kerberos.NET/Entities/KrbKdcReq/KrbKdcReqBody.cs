using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;
using System.Xml.Serialization;
using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum KdcOptions
    {
        /*
         KDCOptions      ::= KerberosFlags
        -- reserved(0),
        -- forwardable(1),
        -- forwarded(2),
        -- proxiable(3),
        -- proxy(4),
        -- allow-postdate(5),
        -- postdated(6),
        -- unused7(7),
        -- renewable(8),
        -- unused9(9),
        -- unused10(10),
        -- opt-hardware-auth(11),
        -- unused12(12),
        -- unused13(13),
-- 15 is reserved for canonicalize
        -- unused15(15),
-- 26 was unused in 1510
        -- disable-transited-check(26),
--
        -- renewable-ok(27),
        -- enc-tkt-in-skey(28),
        -- renew(30),
        -- validate(31)
         */

        Reserved = 0,
        Forwardable = 1 << 30,
        Forwarded = 1 << 29,
        Proxiable = 1 << 28,
        Proxy = 1 << 27,
        AllowPostdate = 1 << 26,
        Postdated = 1 << 25,
        Unused7 = 1 << 24,
        Renewable = 1 << 23,
        Unused9 = 1 << 22,
        Unused10 = 1 << 21,
        OptHardwareAuth = 1 << 20,
        Unused12 = 1 << 19,
        Unused13 = 1 << 18,
        Canonicalize = 1 << 17,
        DisableTransitedCheck = 1 << 6,
        RenewableOk = 1 << 5,
        EncTktInSkey = 1 << 4,
        Renew = 1 << 3,
        Validate = 1 << 2
    }

    public class KrbKdcReqBody
    {
        public KrbKdcReqBody()
        {
        }

        public KdcOptions KdcOptions { get; private set; }
        public PrincipalName CName { get; private set; }
        public string Realm { get; private set; }
        public PrincipalName SName { get; private set; }
        public DateTimeOffset From { get; private set; }
        public DateTimeOffset Till { get; private set; }
        public DateTimeOffset RTime { get; private set; }
        public int Nonce { get; private set; }
        public IEnumerable<EncryptionType> EType { get; private set; }
        public EncryptedData EncAuthorizationData { get; private set; }
        public IEnumerable AdditionalTickets { get; private set; }

        /*
         KDC-REQ-BODY    ::= SEQUENCE {
                kdc-options             [0] KDCOptions,
                cname                   [1] PrincipalName OPTIONAL
                                            -- Used only in AS-REQ --,
                realm                   [2] Realm
                                            -- Server's realm
                                            -- Also client's in AS-REQ --,
                sname                   [3] PrincipalName OPTIONAL,
                from                    [4] KerberosTime OPTIONAL,
                till                    [5] KerberosTime,
                rtime                   [6] KerberosTime OPTIONAL,
                nonce                   [7] UInt32,
                etype                   [8] SEQUENCE OF Int32 -- EncryptionType
                                            -- in preference order --,
                addresses               [9] HostAddresses OPTIONAL,
                enc-authorization-data  [10] EncryptedData OPTIONAL
                                            -- AuthorizationData --,
                additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                                                -- NOTE: not empty
        }
        */

        public KrbKdcReqBody Decode(Asn1Element element)
        {
            var body = this;

            for (var i = 0; i < element.Count; i++)
            {
                var child = element[i];

                switch (child.ContextSpecificTag)
                {
                    case 0:
                        body.KdcOptions = (KdcOptions)child[0].AsLong();
                        break;
                    case 1:
                        body.CName = new PrincipalName().Decode(child[0], null);
                        break;
                    case 2:
                        body.Realm = child[0].AsString();
                        break;
                    case 3:
                        body.SName = new PrincipalName().Decode(child[0], body.Realm);
                        break;
                    case 4:
                        body.From = child[0].AsDateTimeOffset();
                        break;
                    case 5:
                        body.Till = child[0].AsDateTimeOffset();
                        break;
                    case 6:
                        body.RTime = child[0].AsDateTimeOffset();
                        break;
                    case 7:
                        body.Nonce = child[0].AsInt();
                        break;
                    case 8:
                        body.EType = ParseETypes(child[0]);
                        break;
                    case 9:
                        break;
                    case 10:
                        body.EncAuthorizationData = new EncryptedData().Decode(child[0]);
                        break;
                    case 11:
                        body.AdditionalTickets = DecodeAdditionalTickets(child[0]);
                        break;

                }
            }

            return body;
        }

        private IEnumerable<Ticket> DecodeAdditionalTickets(Asn1Element element)
        {
            var list = new List<Ticket>();

            for (var i = 0; i < element.Count; i++)
            {
                list.Add(new Ticket().Decode(element[i]));
            }

            return list;
        }

        private static IEnumerable<EncryptionType> ParseETypes(Asn1Element element)
        {
            var etypes = new List<EncryptionType>();

            for (var i = 0; i < element.Count; i++)
            {
                etypes.Add((EncryptionType)element[i].AsInt());
            }

            return etypes;
        }
    }
}