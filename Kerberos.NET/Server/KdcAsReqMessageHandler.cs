using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Server
{
    public class KdcAsReqMessageHandler : KdcMessageHandlerBase
    {
        private static readonly PaDataType[] PreAuthAscendingPriority = new PaDataType[]
        {
            PaDataType.PA_PK_AS_REQ,
            PaDataType.PA_ENC_TIMESTAMP,
        };

        private readonly ILogger<KdcAsReqMessageHandler> logger;

        public KdcAsReqMessageHandler(ReadOnlyMemory<byte> message, ListenerOptions options)
            : base(message, options)
        {
            this.logger = options.Log.CreateLoggerSafe<KdcAsReqMessageHandler>();

            PostProcessAuthHandlers[PaDataType.PA_ETYPE_INFO2] = service => new PaDataETypeInfo2Handler(service);

            RegisterPreAuthHandlers(PostProcessAuthHandlers);
        }

        protected override MessageType MessageType => MessageType.KRB_AS_REQ;

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            var asReq = KrbAsReq.DecodeApplication(message);

            SetRealmContext(asReq.Realm);

            return asReq;
        }

        protected override IEnumerable<PaDataType> GetOrderedPreAuth(PreAuthenticationContext preauth)
        {
            var keys = PreAuthHandlers.Keys.Intersect(preauth.Principal.SupportedPreAuthenticationTypes);

            keys = keys.OrderBy(k => Array.IndexOf(PreAuthAscendingPriority, k));

            return keys;
        }

        public override void QueryPreValidate(PreAuthenticationContext context)
        {
            KrbAsReq asReq = (KrbAsReq)context.Message;

            context.Principal = RealmService.Principals.Find(asReq.Body.CName);
            context.ServicePrincipal = RealmService.Principals.Find(KrbPrincipalName.WellKnown.Krbtgt());
        }

        public override async Task QueryPreValidateAsync(PreAuthenticationContext context)
        {
            KrbAsReq asReq = (KrbAsReq)context.Message;

            context.Principal = await RealmService.Principals.FindAsync(asReq.Body.CName);
            context.ServicePrincipal = await RealmService.Principals.FindAsync(KrbPrincipalName.WellKnown.Krbtgt());
        }

        public override void ValidateTicketRequest(PreAuthenticationContext preauth)
        {
            if (preauth.Principal == null)
            {
                return;
            }

            try
            {
                var preauthReq = ProcessPreAuth(preauth);

                if (preauth.PaData == null)
                {
                    preauth.PaData = Array.Empty<KrbPaData>();
                }

                preauth.PaData = preauth.PaData.Union(preauthReq).ToArray();
            }
            catch (KerberosValidationException kex)
            {
                logger.LogWarning(kex, "AS-REQ failed processing for principal {Principal}", preauth.Principal.PrincipalName);

                preauth.Failure = kex;
            }
        }

        public override ReadOnlyMemory<byte> ExecuteCore(PreAuthenticationContext context)
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

            KrbAsReq asReq = (KrbAsReq)context.Message;

            if (context.Principal == null)
            {
                logger.LogInformation("User {User} not found in realm {Realm}", asReq.Body.CName.FullyQualifiedName, RealmService.Name);

                return GenerateError(KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN, null, RealmService.Name, asReq.Body.CName.FullyQualifiedName);
            }

            if (!context.PreAuthenticationSatisfied)
            {
                return RequirePreAuth(context);
            }

            return GenerateAsRep(asReq, context);
        }

        private ReadOnlyMemory<byte> GenerateAsRep(KrbAsReq asReq, PreAuthenticationContext context)
        {
            // 1. detect if specific PAC contents are requested (claims)
            // 2. if requested generate PAC for user
            // 3. stuff PAC into ad-if-relevant pa-data of krbtgt ticket
            // 4. look up krbtgt account
            // 5. encrypt against krbtgt
            // 6. done

            var rst = new ServiceTicketRequest
            {
                Principal = context.Principal,
                EncryptedPartKey = context.EncryptedPartKey,
                ServicePrincipal = context.ServicePrincipal,
                Addresses = asReq.Body.Addresses,
                Nonce = asReq.Body.Nonce,
                IncludePac = true,
                Flags = TicketFlags.Initial | KrbKdcRep.DefaultFlags
            };

            if (!asReq.Body.KdcOptions.HasFlag(KdcOptions.Canonicalize))
            {
                rst.SamAccountName = asReq.Body.CName.FullyQualifiedName;
            }

            if (context.ClientAuthority != PaDataType.PA_NONE)
            {
                rst.Flags |= TicketFlags.PreAuthenticated;
            }

            if (rst.EncryptedPartKey == null)
            {
                rst.EncryptedPartKey = rst.Principal.RetrieveLongTermCredential();
            }

            rst.IncludePac = DetectPacRequirement(asReq) ?? false;

            var asRep = KrbAsRep.GenerateTgt(rst, RealmService);

            if (context.PaData != null)
            {
                asRep.PaData = context.PaData.ToArray();
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
    }
}
