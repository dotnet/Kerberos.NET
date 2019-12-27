using Kerberos.NET.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public abstract class KdcPreAuthenticationHandlerBase
    {
        protected IRealmService Service { get; }

        protected KdcPreAuthenticationHandlerBase(IRealmService service)
        {
            Service = service;
        }

        public virtual Task PostValidate(IKerberosPrincipal principal, List<KrbPaData> preAuthRequirements)
        {
            return Task.CompletedTask;
        }

        public virtual Task<KrbPaData> Validate(KrbKdcReq asReq, PreAuthenticationContext preauth)
        {
            return Validate(asReq, preauth.Principal);
        }

        public virtual Task<KrbPaData> Validate(KrbKdcReq asReq, IKerberosPrincipal principal)
        {
            return Task.FromResult<KrbPaData>(null);
        }
    }
}
