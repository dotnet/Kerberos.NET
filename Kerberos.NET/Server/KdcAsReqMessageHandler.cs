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

        public KdcAsReqMessageHandler(ReadOnlySequence<byte> message, ListenerOptions options)
            : base(message, options)
        {
            postProcessAuthHandlers[PaDataType.PA_ETYPE_INFO2] = service => new PaDataETypeInfo2Handler(service);

            RegisterPreAuthHandlers(postProcessAuthHandlers);
        }

        protected override MessageType MessageType => MessageType.KRB_AS_REQ;

        protected override IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message)
        {
            return KrbAsReq.DecodeApplication(message);
        }

        protected override async Task<ReadOnlyMemory<byte>> ExecuteCore(IKerberosMessage message)
        {
            // 1. check what pre-auth validation is required for user
            // 2. enumerate all pre-auth handlers that are available
            //      - fail hard if required doesn't intersect available
            // 3. if pre-auth is required and not present, return error prompting for it
            // 4. if pre-auth is present, validate it
            // 5. if pre-auth failed, return error
            // 6. if some pre-auth succeeded, return error
            // 7. if all required validation succeeds, generate PAC, TGT, and return it

            KrbAsReq asReq = (KrbAsReq)message;

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

            return await GenerateAsRep(asReq, principal);
        }

        private async Task<ReadOnlyMemory<byte>> GenerateAsRep(KrbKdcReq asReq, IKerberosPrincipal principal)
        {
            // 1. detect if specific PAC contents are requested (claims)
            // 2. if requested generate PAC for user
            // 3. stuff PAC into ad-if-relevant pa-data of krbtgt ticket
            // 4. look up krbtgt account
            // 5. encrypt against krbtgt
            // 6. done

            var requirements = new List<KrbPaData>();

            foreach (var handler in postProcessAuthHandlers)
            {
                await InvokePreAuthHandler(null, principal, requirements, handler.Value);
            }

            var asRep = await KrbAsRep.GenerateTgt(principal, requirements, RealmService, asReq.Body);

            return asRep.EncodeApplication();
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

            return err.EncodeApplication();
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

            return err.EncodeApplication();
        }

        private async Task<IEnumerable<KrbPaData>> ProcessPreAuth(KrbKdcReq asReq, IKerberosPrincipal principal)
        {
            // if there are pre-auth handlers registered check whether they intersect with what the user supports.
            // at some point in the future this should evaluate whether there's at least a m-of-n PA-Data approval
            // this would probably best be driven by some policy check, which would involve coming up with a logic
            // system of some sort. Will leave that as an exercise for future me.

            var invokingAuthTypes = PreAuthHandlers.Keys.Intersect(principal.SupportedPreAuthenticationTypes);

            var preAuthRequirements = new List<KrbPaData>();

            foreach (var preAuthType in invokingAuthTypes)
            {
                await InvokePreAuthHandler(asReq, principal, preAuthRequirements, PreAuthHandlers[preAuthType]);
            }

            // if the pre-auth handlers think auth is required we should check with the
            // post-auth handlers because they may add hints to help the client like if
            // they should use specific etypes or salts.
            //
            // the post-auth handlers will determine if they need to do anything based
            // on their own criteria.

            foreach (var preAuthType in postProcessAuthHandlers)
            {
                var func = preAuthType.Value;

                var handler = func(RealmService);

                await handler.PostValidate(principal, preAuthRequirements);
            }

            return preAuthRequirements;
        }

        private async Task InvokePreAuthHandler(
            KrbKdcReq asReq,
            IKerberosPrincipal principal,
            List<KrbPaData> preAuthRequirements,
            PreAuthHandlerConstructor func
        )
        {
            var handler = func(RealmService);

            var preAuthRequirement = await handler.Validate(asReq, principal);

            if (preAuthRequirement != null)
            {
                preAuthRequirements.Add(preAuthRequirement);
            }
        }
    }
}