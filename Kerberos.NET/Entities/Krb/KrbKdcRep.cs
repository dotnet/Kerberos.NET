using Kerberos.NET.Asn1;
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
                                                  TicketFlags.Initial |
                                                  TicketFlags.Forwardable;

        public static async Task<T> GenerateServiceTicket<T>(
            IKerberosPrincipal principal,
            KerberosKey encPartKey,
            IKerberosPrincipal servicePrincipal,
            KerberosKey serviceKey,
            IRealmService realmService,
            TicketFlags flags = DefaultFlags,
            IEnumerable<KrbHostAddress> addresses = null,
            DateTimeOffset? renewTill = null
        )
            where T : KrbKdcRep, new()
        {
            var sessionKey = KrbEncryptionKey.Generate(serviceKey.EncryptionType);

            var now = realmService.Now();

            var authz = await GenerateAuthorizationData(principal, serviceKey);

            var cname = KrbPrincipalName.FromPrincipal(principal, realm: realmService.Name);

            if (principal.SupportedPreAuthenticationTypes.Any())
            {
                // This is not strictly an accurate way of detecting if the user was pre-authenticated.
                // If pre-auth handlers are registered and the principal has PA-Types available, a request
                // will never make it to this point without getting authenticated.
                //
                // However if no pre-auth handlers are registered, then the PA check is skipped
                // and this isn't technically accurate anymore.
                //
                // TODO: this should tie into the make-believe policy check being used in the 
                // auth handler section

                flags |= TicketFlags.EncryptedPreAuthentication | TicketFlags.PreAuthenticated;
            }

            if (addresses == null)
            {
                addresses = new KrbHostAddress[0];
            }

            var encTicketPart = new KrbEncTicketPart()
            {
                CName = cname,
                Key = sessionKey,
                AuthTime = now,
                StartTime = now - realmService.Settings.MaximumSkew,
                EndTime = now + realmService.Settings.SessionLifetime,
                CRealm = realmService.Name,
                Flags = flags,
                AuthorizationData = authz.ToArray(),
                CAddr = addresses.ToArray(),
                Transited = new KrbTransitedEncoding()
            };

            if (flags.HasFlag(TicketFlags.Renewable))
            {
                // RenewTill should never increase if it was set previously even if this is a renewal pass

                encTicketPart.RenewTill = renewTill ?? now + realmService.Settings.MaximumRenewalWindow;
            }

            var ticket = new KrbTicket()
            {
                Realm = realmService.Name,
                SName = KrbPrincipalName.FromPrincipal(
                    servicePrincipal,
                    PrincipalNameType.NT_SRV_INST,
                    realmService.Name
                ),
                EncryptedPart = KrbEncryptedData.Encrypt(
                    encTicketPart.EncodeApplication(),
                    serviceKey,
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
            encKdcRepPart.KeyExpiration = principal.Expires;
            encKdcRepPart.Realm = realmService.Name;
            encKdcRepPart.SName = ticket.SName;
            encKdcRepPart.Flags = encTicketPart.Flags;
            encKdcRepPart.CAddr = encTicketPart.CAddr;
            encKdcRepPart.Key = sessionKey;
            encKdcRepPart.Nonce = KerberosConstants.GetNonce();
            encKdcRepPart.LastReq = new[] { new KrbLastReq { Type = 0, Value = now } };
            encKdcRepPart.EncryptedPaData = new KrbMethodData
            {
                MethodData = new[]
                {
                    new KrbPaData
                    {
                        Type = PaDataType.PA_SUPPORTED_ETYPES,
                        Value = principal.SupportedEncryptionTypes.AsReadOnly(littleEndian: true).AsMemory()
                    }
                }
            };

            encKdcRepPart.EncodeApplication();

            var rep = new T
            {
                CName = cname,
                CRealm = realmService.Name,
                MessageType = MessageType.KRB_AS_REP,
                Ticket = ticket,
                EncPart = KrbEncryptedData.Encrypt(
                    encKdcRepPart.EncodeApplication(),
                    encPartKey,
                    encKdcRepPart.KeyUsage
                )
            };

            return rep;
        }

        private static async Task<IEnumerable<KrbAuthorizationData>> GenerateAuthorizationData(
            IKerberosPrincipal principal, 
            KerberosKey krbtgt
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

            var pac = await principal.GeneratePac();

            var authz = new List<KrbAuthorizationData>();

            var sequence = new KrbAuthorizationDataSequence
            {
                AuthorizationData = new[]
                {
                    new KrbAuthorizationData
                    {
                        Type = AuthorizationDataType.AdWin2kPac,
                        Data = pac.Encode(krbtgt, krbtgt)
                    }
                }
            };

            authz.Add(new KrbAuthorizationData
            {
                Type = AuthorizationDataType.AdIfRelevant,
                Data = sequence.Encode().AsMemory()
            });

            return authz;
        }
    }
}
