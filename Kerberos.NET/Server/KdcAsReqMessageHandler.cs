using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    using PreAuthHandlerConstructor = Func<IRealmService, KdcPreAuthenticationHandlerBase>;

    public class KdcAsReqMessageHandler : KdcMessageHandlerBase
    {
        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> postProcessAuthHandlers =
                new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        public KdcAsReqMessageHandler(ReadOnlySequence<byte> message, KdcListenerOptions options)
            : base(message, options)
        {
            postProcessAuthHandlers[PaDataType.PA_ETYPE_INFO2] = service => new PaDataETypeInfo2Handler(service);

            RegisterPreAuthHandlers(postProcessAuthHandlers);
        }

        protected override async Task<ReadOnlyMemory<byte>> ExecuteCore(ReadOnlyMemory<byte> message)
        {
            // 1. check what pre-auth validation is required for user
            // 2. enumerate all pre-auth handlers that are available
            //      - fail hard if required doesn't intersect available
            // 3. if pre-auth is required and not present, return error prompting for it
            // 4. if pre-auth is present, validate it
            // 5. if pre-auth failed, return error
            // 6. if some pre-auth succeeded, return error
            // 7. if all required validation succeeds, generate PAC, TGT, and return it

            var asReqMessage = KrbAsReq.DecodeAsApplication(message);

            var asReq = asReqMessage.AsReq;

            await SetRealmContext(asReq.Body.Realm);

            var principal = await RealmService.Principals.Find(asReq.Body.CName.FullyQualifiedName);

            try
            {
                var preAuthRequests = await ProcessPreAuth(asReq, principal);

                if (preAuthRequests.Count() > 0)
                {
                    return RequirePreAuth(preAuthRequests, principal);
                }
            }
            catch (KerberosValidationException kex)
            {
                Log(kex);

                return PreAuthFailed(kex, principal);
            }

            return await GenerateTgt(principal);
        }

        private async Task<ReadOnlyMemory<byte>> GenerateTgt(IKerberosPrincipal principal)
        {
            // 1. detect if specific PAC contents are requested (claims)
            // 2. if requested generate PAC for user
            // 3. stuff PAC into ad-if-relevant pa-data of krbtgt ticket
            // 4. look up krbtgt account
            // 5. encrypt against krbtgt
            // 6. done

            // This is approximately correct such that a client doesn't barf on it
            // But the krbtgt Ticket structure is probably incorrect as far as AD thinks

            var krbtgtPrincipal = await RealmService.Principals.RetrieveKrbtgt();
            var krbtgtKey = await krbtgtPrincipal.RetrieveLongTermCredential();

            var sessionKey = KrbEncryptionKey.Generate(krbtgtKey.EncryptionType);

            var now = RealmService.Now();

            var cname = KrbPrincipalName.FromPrincipal(principal, realm: RealmService.Name);

            var authz = await GenerateAuthorizationData(principal, krbtgtKey);

            var encTicketPart = new KrbEncTicketPart()
            {
                CName = cname,
                Key = sessionKey,
                AuthTime = now,
                StartTime = now - RealmService.Settings.MaximumSkew,
                EndTime = now + RealmService.Settings.SessionLifetime,
                RenewTill = now + RealmService.Settings.MaximumRenewalWindow,
                CRealm = RealmService.Name,
                Flags = TicketFlags.Renewable | TicketFlags.Initial,
                AuthorizationData = authz.ToArray()
            };

            var ticket = new KrbTicket()
            {
                Realm = RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(
                    krbtgtPrincipal,
                    PrincipalNameType.NT_SRV_INST,
                    RealmService.Name
                ),
                EncryptedPart = KrbEncryptedData.Encrypt(
                    encTicketPart.EncodeAsApplication(),
                    krbtgtKey,
                    KeyUsage.Ticket
                )
            };

            var encAsRepPart = new KrbEncAsRepPart
            {
                EncAsRepPart = new KrbEncKdcRepPart
                {
                    AuthTime = encTicketPart.AuthTime,
                    StartTime = encTicketPart.StartTime,
                    EndTime = encTicketPart.EndTime,
                    RenewTill = encTicketPart.RenewTill,
                    Realm = RealmService.Name,
                    SName = ticket.SName,
                    Flags = encTicketPart.Flags,
                    CAddr = encTicketPart.CAddr,
                    Key = sessionKey,
                    Nonce = KerberosConstants.GetNonce(),
                    LastReq = new[] { new KrbLastReq { Type = 0 } }
                }
            };

            var principalSecret = await principal.RetrieveLongTermCredential();

            var asRep = new KrbAsRep
            {
                Response = new KrbKdcRep
                {
                    CName = cname,
                    CRealm = RealmService.Name,
                    MessageType = MessageType.KRB_AS_REP,
                    Ticket = new KrbTicketApplication { Application = ticket },
                    EncPart = KrbEncryptedData.Encrypt(
                        encAsRepPart.EncodeAsApplication(),
                        principalSecret,
                        KeyUsage.EncAsRepPart
                    )
                }
            };

            return asRep.EncodeAsApplication();
        }

        private async Task<IEnumerable<KrbAuthorizationData>> GenerateAuthorizationData(
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

        private ReadOnlyMemory<byte> PreAuthFailed(KerberosValidationException kex, IKerberosPrincipal principal)
        {
            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                EText = kex.Message,
                Realm = RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(principal)
            };

            return err.EncodeAsApplication();
        }

        private ReadOnlyMemory<byte> RequirePreAuth(IEnumerable<KrbPaData> preAuthRequests, IKerberosPrincipal principal)
        {
            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                EText = "",
                Realm = RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(principal),
                EData = new KrbMethodData
                {
                    MethodData = preAuthRequests.ToArray()
                }.Encode().AsMemory()
            };

            return err.EncodeAsApplication();
        }

        private async Task<IEnumerable<KrbPaData>> ProcessPreAuth(KrbKdcReq asReq, IKerberosPrincipal principal)
        {
            var invokingAuthTypes = PreAuthHandlers.Keys.Intersect(principal.SupportedPreAuthenticationTypes);

            var preAuthRequests = new List<KrbPaData>();

            foreach (var preAuthType in invokingAuthTypes)
            {
                await InvokePreAuthHandler(asReq, principal, preAuthRequests, PreAuthHandlers[preAuthType]);
            }

            if (preAuthRequests.Count > 0)
            {
                foreach (var preAuthType in postProcessAuthHandlers)
                {
                    await InvokePreAuthHandler(asReq, principal, preAuthRequests, preAuthType.Value);
                }
            }

            return preAuthRequests;
        }

        private async Task InvokePreAuthHandler(
            KrbKdcReq asReq, 
            IKerberosPrincipal principal, 
            List<KrbPaData> preAuthRequests, 
            PreAuthHandlerConstructor func
        )
        {
            var handler = func(RealmService);

            var preAuthRequest = await handler.Validate(asReq, principal);

            if (preAuthRequest != null)
            {
                preAuthRequests.Add(preAuthRequest);
            }
        }
    }
}