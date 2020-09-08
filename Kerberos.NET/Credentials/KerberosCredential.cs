// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Credentials
{
    public abstract class KerberosCredential
    {
        public IEnumerable<KeyValuePair<EncryptionType, string>> Salts { get; set; } = new List<KeyValuePair<EncryptionType, string>>();

        public string UserName { get; set; }

        public string Domain { get; set; }

        public abstract KerberosKey CreateKey();

        public abstract bool SupportsOptimisticPreAuthentication { get; }

        public Krb5Config Configuration { get; set; }

        public virtual void TransformKdcReq(KrbKdcReq req)
        {
            if (req == null)
            {
                throw new ArgumentNullException(nameof(req));
            }

            var ts = KrbPaEncTsEnc.Now();

            var tsEncoded = ts.Encode();

            var padata = req.PaData.ToList();

            var key = this.CreateKey();

            KrbEncryptedData encData = KrbEncryptedData.Encrypt(
                tsEncoded,
                key,
                KeyUsage.PaEncTs
            );

            padata.Add(new KrbPaData
            {
                Type = PaDataType.PA_ENC_TIMESTAMP,
                Value = encData.Encode()
            });

            req.PaData = padata.ToArray();
        }

        public void IncludePreAuthenticationHints(IEnumerable<KrbPaData> preauth)
        {
            if (preauth == null)
            {
                throw new ArgumentNullException(nameof(preauth));
            }

            foreach (var padata in preauth)
            {
                if (padata.Type != PaDataType.PA_ETYPE_INFO2)
                {
                    continue;
                }

                var etypeInfo = padata.DecodeETypeInfo2();

                this.Salts = etypeInfo.Select(e => new KeyValuePair<EncryptionType, string>(e.EType, e.Salt));
            }
        }

        protected static void TrySplitUserNameDomain(string original, out string username, ref string domain)
        {
            if (string.IsNullOrEmpty(original))
            {
                throw new ArgumentNullException(nameof(original));
            }

            username = original;

            var index = original.IndexOf('@');

            if (index > 0 && string.IsNullOrWhiteSpace(domain))
            {
                username = original.Substring(0, index);
                domain = original.Substring(index + 1, original.Length - username.Length - 1);
            }
        }

        public virtual void Validate()
        {
            if (string.IsNullOrWhiteSpace(this.UserName))
            {
                throw new InvalidOperationException("UserName cannot be null or empty");
            }

            if (string.IsNullOrWhiteSpace(this.Domain))
            {
                throw new InvalidOperationException("Domain cannot be null or empty");
            }
        }

        public virtual T DecryptKdcRep<T>(KrbKdcRep kdcRep, KeyUsage keyUsage, Func<ReadOnlyMemory<byte>, T> func)
        {
            if (kdcRep == null)
            {
                throw new ArgumentNullException(nameof(kdcRep));
            }

            return kdcRep.EncPart.Decrypt(
                this.CreateKey(),
                keyUsage,
                func
            );
        }
    }
}
