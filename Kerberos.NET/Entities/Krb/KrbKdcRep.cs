using Kerberos.NET.Crypto;
using Kerberos.NET.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

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

        public static async Task<T> GenerateServiceTicket<T>(ServiceTicketRequest request)
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

            var authz = await GenerateAuthorizationData(request.Principal, request);

            var cname = KrbPrincipalName.FromPrincipal(request.Principal, realm: request.RealmName);

            var sessionKey = KrbEncryptionKey.Generate(request.ServicePrincipalKey.EncryptionType);

            var flags = request.Flags;

            if (request.PreAuthenticationData?.Any(r => r.Type == PaDataType.PA_REQ_ENC_PA_REP) ?? false)
            {
                flags |= TicketFlags.EncryptedPreAuthentication;
            }

            var addresses = request.Addresses;

            if (addresses == null)
            {
                addresses = new KrbHostAddress[0];
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
                AuthorizationData = authz.ToArray(),
                CAddr = addresses.ToArray(),
                Transited = new KrbTransitedEncoding()
            };

            if (flags.HasFlag(TicketFlags.Renewable))
            {
                // RenewTill should never increase if it was set previously even if this is a renewal pass

                encTicketPart.RenewTill = request.RenewTill;
            }

            var ticket = new KrbTicket()
            {
                Realm = request.RealmName,
                SName = KrbPrincipalName.FromPrincipal(
                    request.ServicePrincipal,
                    PrincipalNameType.NT_SRV_INST,
                    request.RealmName
                ),
                EncryptedPart = KrbEncryptedData.Encrypt(
                    encTicketPart.EncodeApplication(),
                    request.ServicePrincipalKey,
                    KeyUsage.Ticket
                )
            };

            KrbEncKdcRepPart encKdcRepPart;

            if (typeof(T) == typeof(KrbAsRep))
            {
                encKdcRepPart = new KrbEncAsRepPart();
            }
            else if (typeof(T) == typeof(KrbTgsRep))
            {
                encKdcRepPart = new KrbEncTgsRepPart();
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
                CName = cname,
                CRealm = request.RealmName,
                MessageType = MessageType.KRB_AS_REP,
                Ticket = ticket,
                EncPart = KrbEncryptedData.Encrypt(
                    encKdcRepPart.EncodeApplication(),
                    request.EncryptedPartKey,
                    encKdcRepPart.KeyUsage
                )
            };

            return rep;
        }

        private static async Task<IEnumerable<KrbAuthorizationData>> GenerateAuthorizationData(
            IKerberosPrincipal principal,
            ServiceTicketRequest request
        )
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
                var pac = await principal.GeneratePac();

                var sequence = new KrbAuthorizationDataSequence
                {
                    AuthorizationData = new[]
                    {
                        new KrbAuthorizationData
                        {
                            Type = AuthorizationDataType.AdWin2kPac,
                            Data = pac.Encode(request.ServicePrincipalKey, request.ServicePrincipalKey)
                        }
                    }
                };

                authz.Add(new KrbAuthorizationData
                {
                    Type = AuthorizationDataType.AdIfRelevant,
                    Data = sequence.Encode().AsMemory()
                });
            }

            return authz;
        }
    }
}
