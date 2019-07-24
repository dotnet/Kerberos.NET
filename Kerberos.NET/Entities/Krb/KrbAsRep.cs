using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Server;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsRep : IAsn1ApplicationEncoder<KrbAsRep>
    {
        internal const int ApplicationTagValue = 11;
        internal static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, ApplicationTagValue);

        private const TicketFlags DefaultFlags = TicketFlags.Renewable |
                                                 TicketFlags.Initial |
                                                 TicketFlags.Forwardable;

        public KrbAsRep DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return Decode(ApplicationTag, data);
        }

        public ReadOnlyMemory<byte> EncodeAsApplication()
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                if (this.Response != null)
                {
                    this.Response.Encode(writer);
                }

                writer.PopSequence(ApplicationTag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }

        public static async Task<KrbAsRep> GenerateTgt(
            IKerberosPrincipal principal,
            IEnumerable<KrbPaData> requirements,
            IRealmService realmService,
            KrbKdcReqBody asReq)
        {
            // This is approximately correct such that a client doesn't barf on it
            // The krbtgt Ticket structure is probably correct as far as AD thinks
            // Modulo the PAC, at least.

            var servicePrincipal = await realmService.Principals.RetrieveKrbtgt();

            KrbAsRep asRep = await GenerateServiceTicket(principal, servicePrincipal, realmService, MessageType.KRB_AS_REP, asReq.Addresses);

            asRep.Response.PaData = requirements.ToArray();

            return asRep;
        }

        public static async Task<KrbAsRep> GenerateServiceTicket(
            IKerberosPrincipal principal,
            IKerberosPrincipal servicePrincipal,
            IRealmService realmService,
            MessageType messageType,
            IEnumerable<KrbHostAddress> addresses = null
        )
        {
            var serviceKey = await servicePrincipal.RetrieveLongTermCredential();

            var sessionKey = KrbEncryptionKey.Generate(serviceKey.EncryptionType);

            var now = realmService.Now();

            var authz = await GenerateAuthorizationData(principal, serviceKey);

            var cname = KrbPrincipalName.FromPrincipal(principal, realm: realmService.Name);

            var flags = DefaultFlags;

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

            var encTicketPart = new KrbEncTicketPart()
            {
                CName = cname,
                Key = sessionKey,
                AuthTime = now,
                StartTime = now - realmService.Settings.MaximumSkew,
                EndTime = now + realmService.Settings.SessionLifetime,
                RenewTill = now + realmService.Settings.MaximumRenewalWindow,
                CRealm = realmService.Name,
                Flags = flags,
                AuthorizationData = authz.ToArray(),
                CAddr = addresses.ToArray(),
                Transited = new KrbTransitedEncoding()
            };

            var ticket = new KrbTicket()
            {
                Realm = realmService.Name,
                SName = KrbPrincipalName.FromPrincipal(
                    servicePrincipal,
                    PrincipalNameType.NT_SRV_INST,
                    realmService.Name
                ),
                EncryptedPart = KrbEncryptedData.Encrypt(
                    encTicketPart.EncodeAsApplication(),
                    serviceKey,
                    KeyUsage.Ticket
                )
            };

            var encKdcRepPart = new KrbEncKdcRepPart
            {
                AuthTime = encTicketPart.AuthTime,
                StartTime = encTicketPart.StartTime,
                EndTime = encTicketPart.EndTime,
                RenewTill = encTicketPart.RenewTill,
                KeyExpiration = principal.Expires,
                Realm = realmService.Name,
                SName = ticket.SName,
                Flags = encTicketPart.Flags,
                CAddr = encTicketPart.CAddr,
                Key = sessionKey,
                Nonce = KerberosConstants.GetNonce(),
                LastReq = new[] { new KrbLastReq { Type = 0, Value = now } },
                EncryptedPaData = new KrbMethodData
                {
                    MethodData = new[]
                        {
                            new KrbPaData
                            {
                                Type = PaDataType.PA_SUPPORTED_ETYPES,
                                Value = principal.SupportedEncryptionTypes.AsReadOnly(littleEndian: true).AsMemory()
                            }
                        }
                }
            };

            ReadOnlyMemory<byte> encodedEncPart;

            if (messageType == MessageType.KRB_AS_REP)
            {
                encodedEncPart = new KrbEncAsRepPart
                {
                    EncAsRepPart = encKdcRepPart
                }.EncodeAsApplication();
            }
            else
            {
                encodedEncPart = new KrbEncTgsRepPart
                {
                    EncTgsRepPart = encKdcRepPart
                }.EncodeAsApplication();
            }

            var principalSecret = await principal.RetrieveLongTermCredential();

            var asRep = new KrbAsRep
            {
                Response = new KrbKdcRep
                {
                    CName = cname,
                    CRealm = realmService.Name,
                    MessageType = MessageType.KRB_AS_REP,
                    Ticket = new KrbTicketApplication { Application = ticket },
                    EncPart = KrbEncryptedData.Encrypt(
                        encodedEncPart,
                        principalSecret,
                        KeyUsage.EncAsRepPart
                    )
                }
            };

            return asRep;
        }

        private static async Task<IEnumerable<KrbAuthorizationData>> GenerateAuthorizationData(
            IKerberosPrincipal principal, KerberosKey krbtgt
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
