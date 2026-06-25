// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace LocalKdcSample
{
    /// <summary>
    /// A tiny in-memory account database that stands in for a "global" KDC/Active Directory.
    /// Everything the local KDC needs to authenticate a user and issue tickets lives here,
    /// on the server box, instead of off-box in a domain controller.
    ///
    /// The store is the single source of truth for key material so that:
    ///   * the KDC can validate the user's PA-ENC-TIMESTAMP and encrypt tickets, and
    ///   * the service (the IAKerb acceptor) can decrypt the AP-REQ it receives,
    /// all derive identical keys for a given principal.
    /// </summary>
    internal class LocalSecurityStore
    {
        // The realm served by this local KDC. There is no DNS/SRV lookup - everything is in-proc.
        public const string Realm = "LOCALHOST.LOCAL";

        // A fixed krbtgt key. In a real deployment this would be a randomly generated,
        // securely stored secret. Here it just needs to be stable for the lifetime of the KDC.
        private static readonly byte[] KrbtgtSecret = new byte[]
        {
            0x73, 0x10, 0xf2, 0x4a, 0x9c, 0x21, 0x55, 0xde,
            0x01, 0xbb, 0x6e, 0x37, 0x88, 0x44, 0xc0, 0x19
        };

        // principal name (lower-cased) -> clear-text password.
        // In production you would store password-derived keys, not the passwords themselves.
        private readonly Dictionary<string, string> accounts = new(StringComparer.OrdinalIgnoreCase);

        public LocalSecurityStore()
        {
            // A user principal that will authenticate to the local KDC. Accounts are keyed by the
            // canonical name the KDC looks them up by (for a user, the enterprise/UPN form).
            this.AddAccount(UserPrincipalName, "P@ssw0rd!");

            // The service principal hosting the IAkerb acceptor. The AP-REQ the server
            // receives is encrypted with this principal's long-term key.
            this.AddAccount(ServiceSpn, "S3rv1ce!");
        }

        /// <summary>
        /// The UPN of the user principal that authenticates to the local KDC.
        /// </summary>
        public const string UserPrincipalName = "user@" + Realm;

        /// <summary>
        /// The SPN of the local service the client authenticates to.
        /// </summary>
        public const string ServiceSpn = "host/appservice.localhost.local";

        public void AddAccount(string principalName, string password)
        {
            this.accounts[principalName] = password;
        }

        public bool Exists(string principalName)
        {
            return this.accounts.ContainsKey(principalName) ||
                   principalName.StartsWith("krbtgt", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Derives the long-term key for a principal. The exact same construction must be
        /// used everywhere the key is needed (KDC encryption and service decryption) so that
        /// salts line up and the keys match.
        /// </summary>
        public KerberosKey GetLongTermKey(string principalName, EncryptionType etype)
        {
            if (principalName.StartsWith("krbtgt", StringComparison.OrdinalIgnoreCase))
            {
                return new KerberosKey(
                    password: KrbtgtSecret,
                    principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, new[] { "krbtgt" }),
                    etype: EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    saltType: SaltType.ActiveDirectoryUser
                );
            }

            if (!this.accounts.TryGetValue(principalName, out var password))
            {
                throw new InvalidOperationException($"Principal '{principalName}' is not in the local store.");
            }

            return new KerberosKey(
                password: password,
                principalName: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, new[] { principalName }),
                etype: etype,
                saltType: SaltType.ActiveDirectoryUser
            );
        }

        /// <summary>
        /// Builds the keytab the service uses to decrypt the AP-REQ. It is derived from the
        /// very same secret the KDC uses to encrypt the service ticket, so decryption succeeds.
        /// </summary>
        public KeyTable GetServiceKeyTable(string spn)
        {
            if (!this.accounts.TryGetValue(spn, out var password))
            {
                throw new InvalidOperationException($"Service '{spn}' is not in the local store.");
            }

            return new KeyTable(
                new KerberosKey(
                    password,
                    principalName: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Realm, new[] { spn }),
                    saltType: SaltType.ActiveDirectoryUser
                )
            );
        }
    }
}
