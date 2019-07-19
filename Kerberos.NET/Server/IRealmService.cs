using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public interface IRealmService
    {
        IRealmSettings Settings { get; }

        IPrincipalService Principals { get; }
        string Name { get; }

        DateTimeOffset Now();
    }

    public interface IPrincipalService
    {
        Task<IKerberosPrincipal> Find(string principalName);

        Task<IKerberosPrincipal> RetrieveKrbtgt();
    }

    public interface IRealmSettings
    {
        TimeSpan MaximumSkew { get; }

        TimeSpan SessionLifetime { get; }

        TimeSpan MaximumRenewalWindow { get; }
    }

    public interface IKerberosPrincipal
    {
        IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; set; }

        string PrincipalName { get; set; }

        Task<KerberosKey> RetrieveLongTermCredential();

        Task<PrivilegedAttributeCertificate> GeneratePac();
    }
}
