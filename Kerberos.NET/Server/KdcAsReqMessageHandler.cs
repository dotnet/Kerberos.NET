using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
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
        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> PostProcessAuthHandlers =
                new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        private static readonly PaDataType[] PreAuthAscendingPriority = new PaDataType[]
        {
            PaDataType.PA_PK_AS_REQ,
            PaDataType.PA_ENC_TIMESTAMP,
        };

        private readonly ILogger<KdcAsReqMessageHandler> logger;

        public KdcAsReqMessageHandler(ReadOnlySequence<byte> message, ListenerOptions options)
            : base(message, options)
        {
            this.logger = options.Log.CreateLoggerSafe<KdcAsReqMessageHandler>();

            PostProcessAuthHandlers[PaDataType.PA_ETYPE_INFO2] = service => new PaDataETypeInfo2Handler(service);

            RegisterPreAuthHandlers(PostProcessAuthHandlers);
        }

        protected override MessageType MessageType => MessageType.KRB_AS_REQ;

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            return KrbAsReq.DecodeApplication(message);
        }

        public override async Task<PreAuthenticationContext> ValidateTicketRequest(IKerberosMessage message)
        {
            KrbAsReq asReq = (KrbAsReq)message;

            await SetRealmContext(asReq.Realm);

            var username = asReq.Body.CName.FullyQualifiedName;

            var principal = await RealmService.Principals.Find(username);

            var preauth = new PreAuthenticationContext { Principal = principal };

            if (preauth.Principal == null)
            {
                return preauth;
            }

            try
            {
                var preauthReq = await ProcessPreAuth(preauth, asReq);

                if (preauth.PaData == null)
                {
                    preauth.PaData = Array.Empty<KrbPaData>();
                }

                preauth.PaData = preauth.PaData.Union(preauthReq).ToArray();
            }
            catch (KerberosValidationException kex)
            {
                logger.LogWarning(kex, "AS-REQ failed processing for principal {Principal}", principal);

                preauth.Failure = kex;
            }

            return preauth;
        }

        public override async Task<ReadOnlyMemory<byte>> ExecuteCore(IKerberosMessage message, PreAuthenticationContext context)
        {
            // 1. check what pre-auth validation is required for user
            // 2. enumerate all pre-auth handlers that are available
            //      - fail hard if required doesn't intersect available
            // 3. if pre-auth is required and not present, return error prompting for it
            // 4. if pre-auth is present, validate it
            // 5. if pre-auth failed, return error
            // 6. if some pre-auth succeeded, return error
            // 7. if all required validation succeeds, generate PAC, TGT, and return it

            if (context.Failure != null)
            {
                return PreAuthFailed(context);
            }

            KrbAsReq asReq = (KrbAsReq)message;

            if (context.Principal == null)
            {
                logger.LogInformation("User {User} not found in realm {Realm}", asReq.Body.CName.FullyQualifiedName, RealmService.Name);

                return GenerateError(KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN, null, RealmService.Name, asReq.Body.CName.FullyQualifiedName);
            }

            if (!context.PreAuthenticationSatisfied)
            {
                return RequirePreAuth(context);
            }

            return await GenerateAsRep(context, asReq);
        }

        private async Task<ReadOnlyMemory<byte>> GenerateAsRep(PreAuthenticationContext preauth, KrbAsReq asReq)
        {
            // 1. detect if specific PAC contents are requested (claims)
            // 2. if requested generate PAC for user
            // 3. stuff PAC into ad-if-relevant pa-data of krbtgt ticket
            // 4. look up krbtgt account
            // 5. encrypt against krbtgt
            // 6. done

            var rst = new ServiceTicketRequest
            {
                Principal = preauth.Principal,
                EncryptedPartKey = preauth.EncryptedPartKey,
                Addresses = asReq.Body.Addresses,
                Nonce = asReq.Body.Nonce,
                IncludePac = true,
                Flags = TicketFlags.Initial | KrbKdcRep.DefaultFlags
            };

            if (rst.EncryptedPartKey == null)
            {
                rst.EncryptedPartKey = await rst.Principal.RetrieveLongTermCredential();
            }

            var pacRequest = asReq.PaData.FirstOrDefault(pa => pa.Type == PaDataType.PA_PAC_REQUEST);

            if (pacRequest != null)
            {
                var paPacRequest = KrbPaPacRequest.Decode(pacRequest.Value);

                rst.IncludePac = paPacRequest.IncludePac;
            }

            var asRep = await KrbAsRep.GenerateTgt(rst, RealmService);

            if (preauth.PaData != null)
            {
                asRep.PaData = preauth.PaData.ToArray();
            }

            return asRep.EncodeApplication();
        }

        private ReadOnlyMemory<byte> PreAuthFailed(PreAuthenticationContext context)
        {
            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_FAILED,
                EText = context.Failure.Message,
                Realm = RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(context.Principal)
            };

            return err.EncodeApplication();
        }

        private ReadOnlyMemory<byte> RequirePreAuth(PreAuthenticationContext context)
        {
            logger.LogTrace("AS-REQ requires pre-auth for user {User}", context.Principal.PrincipalName);

            var err = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                EText = "",
                Realm = RealmService.Name,
                SName = KrbPrincipalName.FromPrincipal(context.Principal),
                EData = new KrbMethodData
                {
                    MethodData = context.PaData.ToArray()
                }.Encode()
            };

            return err.EncodeApplication();
        }

        private async Task<IEnumerable<KrbPaData>> ProcessPreAuth(PreAuthenticationContext preauth, KrbKdcReq asReq)
        {
            // if there are pre-auth handlers registered check whether they intersect with what the user supports.
            // at some point in the future this should evaluate whether there's at least a m-of-n PA-Data approval
            // this would probably best be driven by some policy check, which would involve coming up with a logic
            // system of some sort. Will leave that as an exercise for future me.

            IEnumerable<PaDataType> invokingAuthTypes = GetOrderedPreAuth(preauth);

            var preAuthRequirements = new List<KrbPaData>();

            foreach (var preAuthType in invokingAuthTypes)
            {
                await InvokePreAuthHandler(asReq, preauth, preAuthRequirements, PreAuthHandlers[preAuthType]);
            }

            // if the pre-auth handlers think auth is required we should check with the
            // post-auth handlers because they may add hints to help the client like if
            // they should use specific etypes or salts.
            //
            // the post-auth handlers will determine if they need to do anything based
            // on their own criteria.

            foreach (var preAuthType in PostProcessAuthHandlers)
            {
                var func = preAuthType.Value;

                var handler = func(RealmService);

                await handler.PostValidate(preauth.Principal, preAuthRequirements);
            }

            return preAuthRequirements;
        }

        private IEnumerable<PaDataType> GetOrderedPreAuth(PreAuthenticationContext preauth)
        {
            var keys = PreAuthHandlers.Keys.Intersect(preauth.Principal.SupportedPreAuthenticationTypes);

            keys = keys.OrderBy(k => Array.IndexOf(PreAuthAscendingPriority, k));

            return keys;
        }

        private async Task InvokePreAuthHandler(
            KrbKdcReq asReq,
            PreAuthenticationContext preauth,
            List<KrbPaData> preAuthRequirements,
            PreAuthHandlerConstructor func
        )
        {
            var handler = func(RealmService);

            var preAuthRequirement = await handler.Validate(asReq, preauth);

            if (preAuthRequirement != null)
            {
                preAuthRequirements.Add(preAuthRequirement);
            }
        }
    }
}
