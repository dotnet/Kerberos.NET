using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

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

        Task<IKerberosPrincipal> Find(KrbPrincipalName principalName);

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

        SupportedEncryptionTypes SupportedEncryptionTypes { get; set; }

        string PrincipalName { get; set; }

        DateTimeOffset? Expires { get; set; }

        Task<KerberosKey> RetrieveLongTermCredential();

        Task<PrivilegedAttributeCertificate> GeneratePac();
    }
}
