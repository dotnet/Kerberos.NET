// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;

namespace LocalKdcSample
{
    /// <summary>
    /// Adapts the <see cref="LocalSecurityStore"/> to the interfaces the KDC pipeline expects.
    /// A single instance describes one realm that is entirely backed by the local store.
    /// </summary>
    internal class LocalRealmService : IRealmService
    {
        private readonly LocalSecurityStore store;

        public LocalRealmService(LocalSecurityStore store, Krb5Config config)
        {
            this.store = store;
            this.Configuration = config;
        }

        public string Name => LocalSecurityStore.Realm;

        public IRealmSettings Settings => new LocalRealmSettings();

        public IPrincipalService Principals => new LocalPrincipalService(this.store);

        public ITrustedRealmService TrustedRealms => new LocalTrustedRealms();

        public Krb5Config Configuration { get; }

        public DateTimeOffset Now() => DateTimeOffset.UtcNow;
    }

    internal class LocalRealmSettings : IRealmSettings
    {
        public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);

        public TimeSpan SessionLifetime => TimeSpan.FromHours(10);

        public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);

        public KerberosCompatibilityFlags Compatibility =>
            KerberosCompatibilityFlags.IsolateRealmsConsistently |
            KerberosCompatibilityFlags.EnableSpecCompliantCNameHandling;
    }

    /// <summary>
    /// There are no cross-realm trusts in this sample - everything resolves locally.
    /// </summary>
    internal class LocalTrustedRealms : ITrustedRealmService
    {
        public IRealmReferral ProposeTransit(KrbTgsReq tgsReq, PreAuthenticationContext context) => null;
    }

    /// <summary>
    /// Looks principals up in the local store.
    /// </summary>
    internal class LocalPrincipalService : IPrincipalService
    {
        private readonly LocalSecurityStore store;

        public LocalPrincipalService(LocalSecurityStore store)
        {
            this.store = store;
        }

        public Task<IKerberosPrincipal> FindAsync(KrbPrincipalName principalName, string realm = null)
        {
            return Task.FromResult(this.Find(principalName, realm));
        }

        public IKerberosPrincipal Find(KrbPrincipalName principalName, string realm = null)
        {
            var name = principalName.FullyQualifiedName;

            if (!this.store.Exists(name))
            {
                return null;
            }

            return new LocalKerberosPrincipal(this.store, name);
        }

        // PKINIT is not used in this sample, so no KDC certificate or DH key cache is needed.
        public X509Certificate2 RetrieveKdcCertificate() => null;

        public IExchangeKey RetrieveKeyCache(KeyAgreementAlgorithm algorithm) => null;

        public IExchangeKey CacheKey(IExchangeKey key) => key;
    }

    /// <summary>
    /// A principal whose secrets come from the local store.
    /// </summary>
    internal class LocalKerberosPrincipal : IKerberosPrincipal
    {
        private static readonly SecurityIdentifier DomainSid = new(
            IdentifierAuthority.NTAuthority,
            new uint[] { 21, 2117794349, 2155833029, 3637845091 },
            0
        );

        private readonly LocalSecurityStore store;

        public LocalKerberosPrincipal(LocalSecurityStore store, string principalName)
        {
            this.store = store;
            this.PrincipalName = principalName;
            this.Expires = DateTimeOffset.UtcNow.AddYears(1);
        }

        public string PrincipalName { get; }

        public DateTimeOffset? Expires { get; }

        // Only password-based pre-auth is offered, which keeps the flow off the PKINIT path.
        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; } = new[]
        {
            PaDataType.PA_ENC_TIMESTAMP
        };

        public SupportedEncryptionTypes SupportedEncryptionTypes { get; } =
            SupportedEncryptionTypes.Aes128CtsHmacSha196 |
            SupportedEncryptionTypes.Aes256CtsHmacSha196 |
            SupportedEncryptionTypes.Aes128CtsHmacSha256 |
            SupportedEncryptionTypes.Aes256CtsHmacSha384;

        public PrincipalType Type
        {
            get
            {
                if (this.PrincipalName.StartsWith("krbtgt", StringComparison.OrdinalIgnoreCase))
                {
                    return PrincipalType.Service;
                }

                return this.PrincipalName.Contains("/") ? PrincipalType.Service : PrincipalType.User;
            }
        }

        public KerberosKey RetrieveLongTermCredential()
        {
            return this.store.GetLongTermKey(this.PrincipalName, EncryptionType.AES256_CTS_HMAC_SHA1_96);
        }

        public KerberosKey RetrieveLongTermCredential(EncryptionType etype)
        {
            return this.store.GetLongTermKey(this.PrincipalName, etype);
        }

        public PrivilegedAttributeCertificate GeneratePac()
        {
            return new PrivilegedAttributeCertificate
            {
                LogonInfo = new PacLogonInfo
                {
                    DomainName = LocalSecurityStore.Realm,
                    UserName = this.PrincipalName,
                    UserDisplayName = this.PrincipalName,
                    DomainSid = DomainSid,
                    UserSid = new SecurityIdentifier(DomainSid, 1138),
                    GroupSid = new SecurityIdentifier(DomainSid, 513),
                    LogonTime = DateTimeOffset.UtcNow,
                    ServerName = "localkdc",
                    UserAccountControl = UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT,
                    UserFlags = UserFlags.LOGON_WINLOGON
                }
            };
        }

        public void Validate(X509Certificate2Collection certificates)
        {
            // No certificate validation - PKINIT is not used in this sample.
        }
    }
}
