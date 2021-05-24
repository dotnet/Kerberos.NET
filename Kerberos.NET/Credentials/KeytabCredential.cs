// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Credentials
{
    public class KeytabCredential : KerberosCredential
    {
        private readonly KeyTable keytab;

        public KeytabCredential(string username, KeyTable keytab, string domain = null)
        {
            TrySplitUserNameDomain(username, out username, ref domain);

            this.UserName = username;

            this.keytab = keytab ?? throw new ArgumentNullException(nameof(keytab));

            if (!string.IsNullOrWhiteSpace(domain))
            {
                this.Domain = domain.ToUpperInvariant();
            }
            else
            {
                var entry = keytab.Entries.FirstOrDefault(e => e.Principal != null);

                if (entry != null)
                {
                    this.Domain = entry.Principal.Realm?.ToUpperInvariant() ??
                                  entry.Principal.FullyQualifiedName.Split('/', '@').Last().ToUpperInvariant();
                }
            }
        }

        public override bool SupportsOptimisticPreAuthentication => this.keytab != null;

        public override KerberosKey CreateKey()
        {
            this.Validate();

            var principalName = KrbPrincipalName.FromString(this.UserName);

            if (this.Salts == null || !this.Salts.Any())
            {
                return this.keytab.GetKey(EncryptionType.RC4_HMAC_NT, principalName);
            }

            foreach (var salt in this.Salts)
            {
                var key = this.keytab.GetKey(salt.Key, principalName);

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }
    }
}
