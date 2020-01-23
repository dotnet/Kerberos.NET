using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    public class FakeRealmService : IRealmService
    {
        public FakeRealmService(string realm)
        {
            Name = realm;
        }

        public IRealmSettings Settings => new FakeRealmSettings();

        public IPrincipalService Principals => new FakePrincipalService();

        public string Name { get; }

        public DateTimeOffset Now()
        {
            return DateTimeOffset.UtcNow;
        }
    }

    internal class FakePrincipalService : IPrincipalService
    {
        public Task<IKerberosPrincipal> Find(string principalName)
        {
            IKerberosPrincipal principal = new FakeKerberosPrincipal(principalName);

            return Task.FromResult(principal);
        }

        public Task<IKerberosPrincipal> Find(KrbPrincipalName principalName)
        {
            return Find(principalName.FullyQualifiedName);
        }

        public Task<X509Certificate2> RetrieveKdcCertificate()
        {
            var file = File.ReadAllBytes("data\\kdc.pfx");

            var cert = new X509Certificate2(file, "p", X509KeyStorageFlags.UserKeySet);

            return Task.FromResult(cert);
        }

        private static readonly Dictionary<KeyAgreementAlgorithm, IExchangeKey> keyCache = new Dictionary<KeyAgreementAlgorithm, IExchangeKey>();

        public Task<IExchangeKey> RetrieveKeyCache(KeyAgreementAlgorithm algorithm)
        {
            if (keyCache.TryGetValue(algorithm, out IExchangeKey key))
            {
                if (key.CacheExpiry < DateTimeOffset.UtcNow)
                {
                    keyCache.Remove(algorithm);
                }
                else
                {
                    return Task.FromResult(key);
                }
            }

            return Task.FromResult<IExchangeKey>(null);
        }

        public Task<IExchangeKey> CacheKey(IExchangeKey key)
        {
            key.CacheExpiry = DateTimeOffset.UtcNow.AddMinutes(60);

            keyCache[key.Algorithm] = key;

            return Task.FromResult(key);
        }

        public Task<IKerberosPrincipal> RetrieveKrbtgt()
        {
            IKerberosPrincipal krbtgt = new FakeKerberosPrincipal("krbtgt");

            return Task.FromResult(krbtgt);
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

        public string PrincipalName { get; set; }

        public DateTimeOffset? Expires { get; set; }

        public Task<PrivilegedAttributeCertificate> GeneratePac()
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

            return Task.FromResult(pac);
        }

        private static readonly KerberosKey TgtKey = new KerberosKey(
            password: KrbTgtKey,
            principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { "krbtgt" }),
            etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
            saltType: SaltType.ActiveDirectoryUser
        );

        private static readonly ConcurrentDictionary<string, KerberosKey> KeyCache = new ConcurrentDictionary<string, KerberosKey>();

        public Task<KerberosKey> RetrieveLongTermCredential()
        {
            KerberosKey key;

            if (PrincipalName == "krbtgt")
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

            return Task.FromResult(key);
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

        public Task Validate(X509Certificate2Collection certificates)
        {
            return Task.CompletedTask;
        }
    }

    internal class FakeRealmSettings : IRealmSettings
    {
        public TimeSpan MaximumSkew => TimeSpan.FromMinutes(5);

        public TimeSpan SessionLifetime => TimeSpan.FromHours(10);

        public TimeSpan MaximumRenewalWindow => TimeSpan.FromDays(7);
    }
}
