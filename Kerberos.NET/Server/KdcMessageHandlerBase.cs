using Kerberos.NET.Entities;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    using PreAuthHandlerConstructor = Func<IRealmService, KdcPreAuthenticationHandlerBase>;

    public abstract class KdcMessageHandlerBase
    {
        private readonly ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers =
            new ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor>();

        protected ReadOnlyMemory<byte> Message { get; }

        protected KdcListenerOptions Options { get; }

        protected IRealmService RealmService { get; private set; }

        protected IDictionary<PaDataType, PreAuthHandlerConstructor> PreAuthHandlers
        {
            get => preAuthHandlers;
        }

        protected KdcMessageHandlerBase(ReadOnlySequence<byte> message, KdcListenerOptions options)
        {
            Message = new ReadOnlyMemory<byte>(message.ToArray());
            Options = options;
        }

        protected async Task SetRealmContext(string realm)
        {
            RealmService = await Options.RealmLocator(realm);
        }

        public virtual Task<ReadOnlyMemory<byte>> Execute()
        {
            try
            {
                return ExecuteCore(Message);
            }
            catch (Exception ex)
            {
                return Task.FromResult(GenerateGenericError(ex, Options));
            }
        }

        protected virtual void Log(Exception ex)
        {
            Options.Log?.WriteLine(KerberosLogSource.Kdc, ex);
        }

        protected abstract Task<ReadOnlyMemory<byte>> ExecuteCore(ReadOnlyMemory<byte> message);

        internal static ReadOnlyMemory<byte> GenerateGenericError(Exception ex, KdcListenerOptions options)
        {
            var krbErr = new KrbError()
            {
                ErrorCode = KerberosErrorCode.KRB_ERR_GENERIC,
                EText = options.IsDebug ? ex.Message : null,
                Realm = options.DefaultRealm,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] {
                        "krbtgt", options.DefaultRealm.ToLower()
                    }
                }
            };

            return krbErr.EncodeAsApplication();
        }

        internal void RegisterPreAuthHandlers(ConcurrentDictionary<PaDataType, PreAuthHandlerConstructor> preAuthHandlers)
        {
            foreach (var handler in preAuthHandlers)
            {
                this.preAuthHandlers[handler.Key] = handler.Value;
            }
        }
    }
}
