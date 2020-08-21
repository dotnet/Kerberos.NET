using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;

namespace Tests.Kerberos.NET
{
    public class FakeRealmService : IRealmService
    {
        public FakeRealmService(string realm)
        {
            Name = realm;
        }

        public IRealmSettings Settings => new FakeRealmSettings();

        public IPrincipalService Principals => new FakePrincipalService(this.Name);

        public string Name { get; }

        public DateTimeOffset Now() => DateTimeOffset.UtcNow;

        public ITrustedRealmService TrustedRealms => new FakeTrustedRealms(this.Name);
    }

    internal class FakeTrustedRealms : ITrustedRealmService
    {
        private readonly string currentRealm;

        public FakeTrustedRealms(string name)
        {
            this.currentRealm = name;
        }

        public IRealmReferral ProposeTransit(KrbTgsReq tgsReq, PreAuthenticationContext context)
        {
            if (!tgsReq.Body.SName.FullyQualifiedName.EndsWith(currentRealm) &&
                !tgsReq.Body.SName.FullyQualifiedName.Contains("not.found"))
            {
                return new FakeRealmReferral(tgsReq.Body);
            }

            return null;
        }
    }

    internal class FakeRealmReferral : IRealmReferral
    {
        private readonly KrbKdcReqBody body;

        public FakeRealmReferral(KrbKdcReqBody body)
        {
            this.body = body;
        }

        public IKerberosPrincipal Refer()
        {
            var fqn = body.SName.FullyQualifiedName;
            var predictedRealm = fqn.Substring(fqn.IndexOf('.') + 1);

            var krbName = KrbPrincipalName.FromString($"krbtgt/{predictedRealm}");

            return new FakeKerberosPrincipal(krbName.FullyQualifiedName);
        }
    }

    internal class FakePrincipalService : IPrincipalService
    {
        private readonly string realm;

        public FakePrincipalService(string realm)
        {
            this.realm = realm;
        }

        public Task<IKerberosPrincipal> FindAsync(KrbPrincipalName principalName, string realm = null)
        {
            return Task.FromResult(Find(principalName));
        }

        public IKerberosPrincipal Find(KrbPrincipalName principalName, string realm = null)
        {
            IKerberosPrincipal principal = null;

            if (principalName.FullyQualifiedName.EndsWith(this.realm, StringComparison.InvariantCultureIgnoreCase) ||
                principalName.FullyQualifiedName.StartsWith("krbtgt", StringComparison.InvariantCultureIgnoreCase) ||
                principalName.Type == PrincipalNameType.NT_PRINCIPAL ||
                principalName.Type == PrincipalNameType.NT_ENTERPRISE)
            {
                principal = new FakeKerberosPrincipal(principalName.FullyQualifiedName);
            }

            return principal;
        }

        public X509Certificate2 RetrieveKdcCertificate()
        {
            var file = File.ReadAllBytes("data\\kdc.pfx");

            var cert = new X509Certificate2(file, "p", X509KeyStorageFlags.UserKeySet);

            return cert;
        }

        private static readonly Dictionary<KeyAgreementAlgorithm, IExchangeKey> keyCache = new Dictionary<KeyAgreementAlgorithm, IExchangeKey>();

        public IExchangeKey RetrieveKeyCache(KeyAgreementAlgorithm algorithm)
        {
            if (keyCache.TryGetValue(algorithm, out IExchangeKey key))
            {
                if (key.CacheExpiry < DateTimeOffset.UtcNow)
                {
                    keyCache.Remove(algorithm);
                }
                else
                {
                    return key;
                }
            }

            return null;
        }

        public IExchangeKey CacheKey(IExchangeKey key)
        {
            key.CacheExpiry = DateTimeOffset.UtcNow.AddMinutes(60);

            keyCache[key.Algorithm] = key;

            return key;
        }
    }

    internal class FakeKerberosPrincipal : IKerberosPrincipal
    {
        private static readonly byte[] KrbTgtKey = new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        };

        private static readonly SecurityIdentifier domainSid = new SecurityIdentifier(
            IdentifierAuthority.NTAuthority,
            new uint[] { 123, 456, 789, 012, 321 },
            0
        );

        private readonly SecurityIdentifier userSid = new SecurityIdentifier(domainSid, 888);

        private readonly SecurityIdentifier groupSid = new SecurityIdentifier(domainSid, 513);

        private readonly static byte[] FakePassword = Encoding.Unicode.GetBytes("P@ssw0rd!");

        private const string realm = "CORP.IDENTITYINTERVENTION.COM";

        public FakeKerberosPrincipal(string principalName)
        {
            PrincipalName = principalName;
            Expires = DateTimeOffset.UtcNow.AddMonths(9999);
        }

        public SupportedEncryptionTypes SupportedEncryptionTypes { get; set; }
             = SupportedEncryptionTypes.Aes128CtsHmacSha196 |
               SupportedEncryptionTypes.Aes256CtsHmacSha196 |
               SupportedEncryptionTypes.Rc4Hmac |
               SupportedEncryptionTypes.DesCbcCrc |
               SupportedEncryptionTypes.DesCbcMd5;

        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; set; } = new[] {
            PaDataType.PA_ENC_TIMESTAMP,
            PaDataType.PA_PK_AS_REQ
        };

        public PrincipalType Type
        {
            get
            {
                if (PrincipalName == "krbtgt" || PrincipalName.Equals($"krbtgt/{realm}", StringComparison.CurrentCultureIgnoreCase))
                {
                    return PrincipalType.Service;
                }

                if (PrincipalName.StartsWith("krbtgt/"))
                {
                    return PrincipalType.TrustedDomain;
                }

                if (PrincipalName.Contains("/"))
                {
                    return PrincipalType.Service;
                }

                return PrincipalType.User;
            }
        }

        public string PrincipalName { get; set; }

        public DateTimeOffset? Expires { get; set; }

        public PrivilegedAttributeCertificate GeneratePac()
        {
            var pac = new PrivilegedAttributeCertificate()
            {
                LogonInfo = new PacLogonInfo
                {
                    DomainName = realm,
                    UserName = PrincipalName,
                    UserDisplayName = PrincipalName,
                    BadPasswordCount = 12,
                    SubAuthStatus = 0,
                    DomainSid = domainSid,
                    UserSid = userSid,
                    GroupSid = groupSid,
                    LogonTime = DateTimeOffset.UtcNow,
                    ServerName = "server",
                    UserAccountControl = UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT,
                    UserFlags = UserFlags.LOGON_WINLOGON,

                }
            };

            return pac;
        }

        private static readonly KerberosKey TgtKey = new KerberosKey(
            password: KrbTgtKey,
            principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { "krbtgt" }),
            etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
            saltType: SaltType.ActiveDirectoryUser
        );

        private static readonly ConcurrentDictionary<string, KerberosKey> KeyCache = new ConcurrentDictionary<string, KerberosKey>();

        public KerberosKey RetrieveLongTermCredential()
        {
            KerberosKey key;

            if (PrincipalName.StartsWith("krbtgt"))
            {
                key = TgtKey;
            }
            else
            {
                key = KeyCache.GetOrAdd(PrincipalName, pn =>
                {
                    EncryptionType etype = ExtractEType(PrincipalName);

                    return new KerberosKey(
                        password: FakePassword,
                        principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { PrincipalName }),
                        etype: etype,
                        saltType: SaltType.ActiveDirectoryUser
                    );
                });
            }

            return key;
        }

        private EncryptionType ExtractEType(string principalName)
        {
            if (principalName.StartsWith("RC4"))
            {
                return EncryptionType.RC4_HMAC_NT;
            }
            else if (principalName.StartsWith("AES128"))
            {
                return EncryptionType.AES128_CTS_HMAC_SHA1_96;
            }
            else if (principalName.StartsWith("AES256"))
            {
                return EncryptionType.AES256_CTS_HMAC_SHA1_96;
            }

            return EncryptionType.AES256_CTS_HMAC_SHA1_96;
        }

        public void Validate(X509Certificate2Collection certificates)
        {
        }
    }

    internal class FakeRealmSettings : IRealmSettings
    {
        public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);

        public TimeSpan SessionLifetime => TimeSpan.FromHours(10);

        public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);
    }
}
