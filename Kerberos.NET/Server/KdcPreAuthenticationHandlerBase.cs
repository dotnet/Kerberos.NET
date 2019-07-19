using System.Threading.Tasks;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public abstract class KdcPreAuthenticationHandlerBase
    {
        protected IRealmService Service { get; }

        protected KdcPreAuthenticationHandlerBase(IRealmService service)
        {
            Service = service;
        }

        public abstract Task<KrbPaData> Validate(KrbKdcReq asReq, IKerberosPrincipal principal);
    }
}
