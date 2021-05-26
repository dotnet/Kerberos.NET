// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;

namespace Tests.Kerberos.NET
{
    internal class FakeKerberosPrincipal : IKerberosPrincipal
    {
        private const string Realm = "CORP.IDENTITYINTERVENTION.COM";

        private static readonly byte[] KrbTgtKey = new byte[]
        {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        };

        private static readonly SecurityIdentifier DomainSid = new SecurityIdentifier(
            IdentifierAuthority.NTAuthority,
            new uint[] { 123, 456, 789, 012, 321 },
            0
        );

        private readonly SecurityIdentifier userSid = new SecurityIdentifier(DomainSid, 888);

        private readonly SecurityIdentifier groupSid = new SecurityIdentifier(DomainSid, 513);

        private static readonly byte[] FakePassword = Encoding.Unicode.GetBytes("P@ssw0rd!");

        public FakeKerberosPrincipal(string principalName)
        {
            this.PrincipalName = principalName;
            this.Expires = DateTimeOffset.UtcNow.AddMonths(9999);
        }

        public SupportedEncryptionTypes SupportedEncryptionTypes { get; set; }
             = SupportedEncryptionTypes.Aes128CtsHmacSha196 |
               SupportedEncryptionTypes.Aes256CtsHmacSha196 |
               SupportedEncryptionTypes.Aes128CtsHmacSha256 |
               SupportedEncryptionTypes.Aes256CtsHmacSha384 |
               SupportedEncryptionTypes.Rc4Hmac |
               SupportedEncryptionTypes.DesCbcCrc |
               SupportedEncryptionTypes.DesCbcMd5;

        public IEnumerable<PaDataType> SupportedPreAuthenticationTypes { get; set; } = new[]
        {
            PaDataType.PA_ENC_TIMESTAMP,
            PaDataType.PA_PK_AS_REQ
        };

        public PrincipalType Type
        {
            get
            {
                if (this.PrincipalName == "krbtgt" || this.PrincipalName.Equals($"krbtgt/{Realm}", StringComparison.CurrentCultureIgnoreCase))
                {
                    return PrincipalType.Service;
                }

                if (this.PrincipalName.StartsWith("krbtgt/", StringComparison.InvariantCultureIgnoreCase))
                {
                    return PrincipalType.TrustedDomain;
                }

                if (this.PrincipalName.Contains("/"))
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
                    DomainName = Realm,
                    UserName = PrincipalName,
                    UserDisplayName = PrincipalName,
                    BadPasswordCount = 12,
                    SubAuthStatus = 0,
                    DomainSid = DomainSid,
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
            principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, new[] { "krbtgt" }),
            etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
            saltType: SaltType.ActiveDirectoryUser
        );

        private static readonly ConcurrentDictionary<string, KerberosKey> KeyCache = new ConcurrentDictionary<string, KerberosKey>();

        public KerberosKey RetrieveLongTermCredential()
        {
            EncryptionType etype = ExtractEType(this.PrincipalName);

            return this.RetrieveLongTermCredential(etype);
        }

        public KerberosKey RetrieveLongTermCredential(EncryptionType etype)
        {
            KerberosKey key;

            if (this.PrincipalName.StartsWith("krbtgt", StringComparison.InvariantCultureIgnoreCase))
            {
                key = TgtKey;
            }
            else
            {
                key = KeyCache.GetOrAdd(etype + this.PrincipalName, pn =>
                {
                    return new KerberosKey(
                        password: FakePassword,
                        principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, new[] { this.PrincipalName }),
                        etype: etype,
                        saltType: SaltType.ActiveDirectoryUser
                    );
                });
            }

            return key;
        }

        private static EncryptionType ExtractEType(string principalName)
        {
            if (principalName.StartsWith("RC4", StringComparison.InvariantCultureIgnoreCase))
            {
                return EncryptionType.RC4_HMAC_NT;
            }
            else if (principalName.StartsWith("AES128", StringComparison.InvariantCultureIgnoreCase))
            {
                return EncryptionType.AES128_CTS_HMAC_SHA1_96;
            }
            else if (principalName.StartsWith("AES128SHA256", StringComparison.InvariantCultureIgnoreCase))
            {
                return EncryptionType.AES128_CTS_HMAC_SHA256_128;
            }
            else if (principalName.StartsWith("AES256", StringComparison.InvariantCultureIgnoreCase))
            {
                return EncryptionType.AES256_CTS_HMAC_SHA1_96;
            }
            else if (principalName.StartsWith("AES256SHA384", StringComparison.InvariantCultureIgnoreCase))
            {
                return EncryptionType.AES256_CTS_HMAC_SHA384_192;
            }

            return EncryptionType.AES256_CTS_HMAC_SHA1_96;
        }

        public void Validate(X509Certificate2Collection certificates)
        {
        }
    }
}
