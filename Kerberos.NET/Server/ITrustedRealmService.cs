using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public interface ITrustedRealmService
    {
        IRealmReferral ProposeTransit(KrbTgsReq tgsReq, PreAuthenticationContext context);
    }
}
