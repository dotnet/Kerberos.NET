// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Credentials
{
    public class KerberosPasswordCredential : KerberosCredential
    {
        private readonly string password;

        public KerberosPasswordCredential(string username, string password, string domain = null)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                throw new ArgumentException("UserName cannot be null", nameof(username));
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password cannot be null", nameof(password));
            }

            TrySplitUserNameDomain(username, out username, ref domain);

            this.UserName = username;
            this.password = password;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                this.Domain = domain.ToUpperInvariant();
            }
        }

        public override bool SupportsOptimisticPreAuthentication => this.Salts != null && this.Salts.Any();

        public override void Validate()
        {
            base.Validate();

            if (string.IsNullOrWhiteSpace(this.password))
            {
                throw new InvalidOperationException("Password cannot be null or empty");
            }
        }

        private readonly object _syncCache = new object();

        private KerberosKey cacheKey;

        public override KerberosKey CreateKey()
        {
            if (this.cacheKey == null)
            {
                lock (this._syncCache)
                {
                    if (this.cacheKey == null)
                    {
                        var principalName = new PrincipalName(PrincipalNameType.NT_PRINCIPAL, this.Domain, new[] { this.UserName });

                        EncryptionType etype = this.Configuration?.Defaults?.DefaultTicketEncTypes?.First() ?? KerberosConstants.GetPreferredETypes().First();
                        string salt = null;

                        if (this.Salts != null && this.Salts.Any())
                        {
                            var etypePreferences = KerberosConstants.GetPreferredETypes(
                                this.Configuration.Defaults.DefaultTicketEncTypes,
                                this.Configuration.Defaults.AllowWeakCrypto
                            ).ToArray();

                            var preferredEtypes = this.Salts.Select(s => s.Key).Intersect(etypePreferences).OrderBy(e => Array.IndexOf(etypePreferences, e));

                            if (!preferredEtypes.Any())
                            {
                                throw new KerberosPolicyException(PaDataType.PA_ENC_TIMESTAMP);
                            }

                            var kv = this.Salts.First(s => s.Key == preferredEtypes.First());

                            etype = kv.Key;
                            salt = kv.Value;
                        }

                        this.cacheKey = new KerberosKey(
                            this.password,
                            principalName: principalName,
                            etype: etype,
                            saltType: SaltType.ActiveDirectoryUser,
                            salt: salt
                        );
                    }
                }
            }

            return this.cacheKey;
        }
    }
}
