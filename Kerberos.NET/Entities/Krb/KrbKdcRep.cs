using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbKdcRep
    {
        public KrbKdcRep()
        {
            ProtocolVersionNumber = 5;
        }

        internal const TicketFlags DefaultFlags = TicketFlags.Renewable |
                                                  TicketFlags.Forwardable;

        public static T GenerateServiceTicket<T>(ServiceTicketRequest request)
            where T : KrbKdcRep, new()
        {
            if (request.EncryptedPartKey == null)
            {
                throw new ArgumentException("A session key must be provided to encrypt the response", nameof(request.EncryptedPartKey));
            }

            if (request.Principal == null)
            {
                throw new ArgumentException("A Principal identity must be provided", nameof(request.Principal));
            }

            if (request.ServicePrincipal == null)
            {
                throw new ArgumentException("A service principal must be provided", nameof(request.ServicePrincipal));
            }

            if (request.ServicePrincipalKey == null)
            {
                throw new ArgumentException("A service principal key must be provided", nameof(request.ServicePrincipalKey));
            }

            var authz = GenerateAuthorizationData(request);

            var sessionKey = KrbEncryptionKey.Generate(request.ServicePrincipalKey.EncryptionType);

            var encTicketPart = CreateEncTicketPart(request, authz.ToArray(), sessionKey);

            bool appendRealm = false;

            if (request.ServicePrincipal.PrincipalName.Contains("/"))
            {
                appendRealm = true;
            }

            var ticket = new KrbTicket()
            {
                Realm = request.RealmName,
                SName = KrbPrincipalName.FromPrincipal(
                    request.ServicePrincipal,
                    PrincipalNameType.NT_SRV_INST,
                    appendRealm ? null : request.RealmName
                ),
                EncryptedPart = KrbEncryptedData.Encrypt(
                    encTicketPart.EncodeApplication(),
                    request.ServicePrincipalKey,
                    KeyUsage.Ticket
                )
            };

            KrbEncKdcRepPart encKdcRepPart;

            KeyUsage keyUsage;

            if (typeof(T) == typeof(KrbAsRep))
            {
                encKdcRepPart = new KrbEncAsRepPart();
                keyUsage = KeyUsage.EncAsRepPart;
            }
            else if (typeof(T) == typeof(KrbTgsRep))
            {
                encKdcRepPart = new KrbEncTgsRepPart();

                keyUsage = request.EncryptedPartKey.Usage ?? KeyUsage.EncTgsRepPartSessionKey;
            }
            else
            {
                throw new InvalidOperationException($"Requested Service Ticket type is neither KrbAsRep nor KrbTgsRep. Type: {typeof(T)}");
            }

            encKdcRepPart.AuthTime = encTicketPart.AuthTime;
            encKdcRepPart.StartTime = encTicketPart.StartTime;
            encKdcRepPart.EndTime = encTicketPart.EndTime;
            encKdcRepPart.RenewTill = encTicketPart.RenewTill;
            encKdcRepPart.KeyExpiration = request.Principal.Expires;
            encKdcRepPart.Realm = request.RealmName;
            encKdcRepPart.SName = ticket.SName;
            encKdcRepPart.Flags = encTicketPart.Flags;
            encKdcRepPart.CAddr = encTicketPart.CAddr;
            encKdcRepPart.Key = sessionKey;
            encKdcRepPart.Nonce = request.Nonce;
            encKdcRepPart.LastReq = new[] { new KrbLastReq { Type = 0, Value = request.Now } };
            encKdcRepPart.EncryptedPaData = new KrbMethodData
            {
                MethodData = new[]
                {
                    new KrbPaData
                    {
                        Type = PaDataType.PA_SUPPORTED_ETYPES,
                        Value = request.Principal.SupportedEncryptionTypes.AsReadOnly(littleEndian: true).AsMemory()
                    }
                }
            };

            var rep = new T
            {
                CName = encTicketPart.CName,
                CRealm = request.RealmName,
                MessageType = MessageType.KRB_AS_REP,
                Ticket = ticket,
                EncPart = KrbEncryptedData.Encrypt(
                    encKdcRepPart.EncodeApplication(),
                    request.EncryptedPartKey,
                    keyUsage
                )
            };

            return rep;
        }

        private static KrbEncTicketPart CreateEncTicketPart(
            ServiceTicketRequest request,
            KrbAuthorizationData[] authorizationDatas,
            KrbEncryptionKey sessionKey)
        {
            var cname = CreateCNameForTicket(request);

            var flags = request.Flags;

            if (request.PreAuthenticationData?.Any(r => r.Type == PaDataType.PA_REQ_ENC_PA_REP) ?? false)
            {
                flags |= TicketFlags.EncryptedPreAuthentication;
            }

            var addresses = request.Addresses;

            if (addresses == null)
            {
                addresses = Array.Empty<KrbHostAddress>();
            }

            var encTicketPart = new KrbEncTicketPart()
            {
                CName = cname,
                Key = sessionKey,
                AuthTime = request.Now,
                StartTime = request.StartTime,
                EndTime = request.EndTime,
                CRealm = request.RealmName,
                Flags = flags,
                AuthorizationData = authorizationDatas,
                CAddr = addresses.ToArray(),
                Transited = new KrbTransitedEncoding()
            };

            if (flags.HasFlag(TicketFlags.Renewable))
            {
                // RenewTill should never increase if it was set previously even if this is a renewal pass

                encTicketPart.RenewTill = request.RenewTill;
            }

            return encTicketPart;
        }

        private static KrbPrincipalName CreateCNameForTicket(ServiceTicketRequest request)
        {
            if (string.IsNullOrEmpty(request.SamAccountName))
            {
                return KrbPrincipalName.FromPrincipal(request.Principal, realm: request.RealmName);
            }

            return new KrbPrincipalName
            {
                Type = PrincipalNameType.NT_PRINCIPAL,
                Name = new[] { request.SamAccountName }
            };
        }

        private static IEnumerable<KrbAuthorizationData> GenerateAuthorizationData(ServiceTicketRequest request)
        {
            // authorization-data is annoying because it's a sequence of 
            // ad-if-relevant, which is a sequence of sequences
            // it ends up looking something like
            //
            // [
            //   {
            //      Type = ad-if-relevant,
            //      Data = 
            //      [
            //        { 
            //           Type = pac,
            //           Data = encoded-pac
            //        },
            //        ...
            //      ],
            //   },
            //   ...
            // ]

            var authz = new List<KrbAuthorizationData>();

            if (request.IncludePac)
            {
                var pac = request.Principal.GeneratePac();

                if (pac != null)
                {
                    var sequence = new KrbAuthorizationDataSequence
                    {
                        AuthorizationData = new[]
                        {
                            new KrbAuthorizationData
                            {
                                Type = AuthorizationDataType.AdWin2kPac,
                                Data = pac.Encode(request.KdcAuthorizationKey, request.ServicePrincipalKey)
                            }
                        }
                    };

                    authz.Add(new KrbAuthorizationData
                    {
                        Type = AuthorizationDataType.AdIfRelevant,
                        Data = sequence.Encode()
                    });
                }
            }

            return authz;
        }
    }
}
