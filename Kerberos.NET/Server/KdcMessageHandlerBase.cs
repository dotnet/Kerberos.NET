using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    using PreAuthHandlerConstructor = Func<IRealmService, KdcPreAuthenticationHandlerBase>;

    public abstract class KdcMessageHandlerBase
    {
        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers =
            new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        private readonly ReadOnlyMemory<byte> message;
        protected readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> PostProcessAuthHandlers =
                new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        protected ListenerOptions Options { get; }

        protected IRealmService RealmService { get; private set; }

        public IDictionary<PaDataType, PreAuthHandlerConstructor> PreAuthHandlers => preAuthHandlers;

        protected abstract MessageType MessageType { get; }

        protected KdcMessageHandlerBase(ReadOnlyMemory<byte> message, ListenerOptions options)
        {
            this.message = message;
            Options = options;
        }

        protected abstract IKerberosMessage DecodeMessageCore(ReadOnlyMemory<byte> message);

        public virtual void ExecutePreValidate(PreAuthenticationContext context)
        {
            InvokeAuthHandlers(
                context,
                PreAuthHandlers.Keys,
                PreAuthHandlers,
                (handler, req, ctx) =>
                {
                    handler.PreValidate(ctx);
                    return true;
                }
            );
        }

        public abstract Task QueryPreValidateAsync(PreAuthenticationContext context);

        public abstract void QueryPreValidate(PreAuthenticationContext context);

        public virtual Task QueryPreExecuteAsync(PreAuthenticationContext context) => Task.CompletedTask;

        public virtual void QueryPreExecute(PreAuthenticationContext context) { }

        public abstract void ValidateTicketRequest(PreAuthenticationContext context);

        public abstract ReadOnlyMemory<byte> ExecuteCore(PreAuthenticationContext context);

        protected void SetRealmContext(string realm)
        {
            RealmService = Options.RealmLocator(realm);
        }

        private IKerberosMessage DecodeMessage(ReadOnlyMemory<byte> message)
        {
            var decoded = DecodeMessageCore(message);

            if (decoded.KerberosProtocolVersionNumber != 5)
            {
                throw new InvalidOperationException($"Message version should be set to v5. Actual: {decoded.KerberosProtocolVersionNumber}");
            }

            if (decoded.KerberosMessageType != MessageType)
            {
                throw new InvalidOperationException($"MessageType should match application class. Actual: {decoded.KerberosMessageType}; Expected: {MessageType}");
            }

            return decoded;
        }

        public virtual void DecodeMessage(PreAuthenticationContext context)
        {
            context.Message = DecodeMessage(message);
        }

        public virtual async Task<ReadOnlyMemory<byte>> ExecuteAsync()
        {
            try
            {
                var context = new PreAuthenticationContext();

                DecodeMessage(context);

                ExecutePreValidate(context);

                await QueryPreValidateAsync(context);

                ValidateTicketRequest(context);

                await QueryPreExecuteAsync(context);

                return ExecuteCore(context);
            }
            catch (Exception ex)
            {
                return GenerateGenericError(ex, Options);
            }
        }

        public virtual ReadOnlyMemory<byte> Execute()
        {
            try
            {
                var context = new PreAuthenticationContext();

                DecodeMessage(context);

                ExecutePreValidate(context);

                QueryPreValidate(context);

                ValidateTicketRequest(context);

                QueryPreExecute(context);

                return ExecuteCore(context);
            }
            catch (Exception ex)
            {
                return GenerateGenericError(ex, Options);
            }
        }

        internal static ReadOnlyMemory<byte> GenerateGenericError(Exception ex, ListenerOptions options)
        {
            KerberosErrorCode error = KerberosErrorCode.KRB_ERR_GENERIC;
            string errorText = options.IsDebug ? $"[Server] {ex}" : null;

            if (ex is KerberosProtocolException kex)
            {
                error = kex.Error.ErrorCode;
                errorText = kex.Message;
            }

            return GenerateError(error, errorText, options.DefaultRealm, "krbtgt");
        }

        internal static ReadOnlyMemory<byte> GenerateError(KerberosErrorCode code, string error, string realm, string sname)
        {
            var krbErr = new KrbError()
            {
                ErrorCode = code,
                EText = error,
                Realm = realm,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] {
                        sname,
                        realm
                    }
                }
            };

            krbErr.StampServerTime();

            return krbErr.EncodeApplication();
        }

        internal void RegisterPreAuthHandlers(ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers)
        {
            foreach (var handler in preAuthHandlers)
            {
                this.preAuthHandlers[handler.Key] = handler.Value;
            }
        }

        protected static bool? DetectPacRequirement(KrbKdcReq asReq)
        {
            var pacRequest = asReq.PaData.FirstOrDefault(pa => pa.Type == PaDataType.PA_PAC_REQUEST);

            if (pacRequest != null)
            {
                var paPacRequest = KrbPaPacRequest.Decode(pacRequest.Value);

                return paPacRequest.IncludePac;
            }

            return null;
        }

        protected void InvokeAuthHandlers(
            PreAuthenticationContext preauth,
            IEnumerable<PaDataType> invokingAuthTypes,
            IDictionary<PaDataType, PreAuthHandlerConstructor> handlers,
            Func<KdcPreAuthenticationHandlerBase, KrbKdcReq, PreAuthenticationContext, bool> preauthExec
        )
        {
            if (preauth.Message is KrbKdcReq asReq)
            {
                foreach (var preAuthType in invokingAuthTypes)
                {
                    var func = handlers[preAuthType];

                    var handler = func(RealmService);

                    if (!preauthExec(handler, asReq, preauth))
                    {
                        break;
                    }
                }
            }
        }

        protected virtual IEnumerable<KrbPaData> ProcessPreAuth(PreAuthenticationContext preauth)
        {
            // if there are pre-auth handlers registered check whether they intersect with what the user supports.
            // at some point in the future this should evaluate whether there's at least a m-of-n PA-Data approval
            // this would probably best be driven by some policy check, which would involve coming up with a logic
            // system of some sort. Will leave that as an exercise for future me.

            IEnumerable<PaDataType> invokingAuthTypes = GetOrderedPreAuth(preauth);

            var preAuthRequirements = new List<KrbPaData>();

            InvokeAuthHandlers(
                preauth,
                invokingAuthTypes,
                PreAuthHandlers,
                (handler, req, context) =>
                {
                    var preAuthRequirement = handler.Validate(req, context);

                    if (preAuthRequirement != null)
                    {
                        preAuthRequirements.Add(preAuthRequirement);
                    }

                    return !context.PreAuthenticationSatisfied;
                }
            );

            // if the pre-auth handlers think auth is required we should check with the
            // post-auth handlers because they may add hints to help the client like if
            // they should use specific etypes or salts.
            //
            // the post-auth handlers will determine if they need to do anything based
            // on their own criteria.

            InvokeAuthHandlers(
               preauth,
               PostProcessAuthHandlers.Keys,
               PostProcessAuthHandlers,
               (handler, req, context) =>
               {
                   handler.PostValidate(context.Principal, preAuthRequirements);
                   return true;
               }
           );

            return preAuthRequirements;
        }

        protected abstract IEnumerable<PaDataType> GetOrderedPreAuth(PreAuthenticationContext preauth);
    }
}
