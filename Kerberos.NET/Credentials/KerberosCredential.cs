using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Credentials
{
    public abstract class KerberosCredential
    {
        public IEnumerable<KeyValuePair<EncryptionType, string>> Salts { get; set; } = new List<KeyValuePair<EncryptionType, string>>();

        public string UserName { get; set; }

        public string Domain { get; set; }

        public abstract KerberosKey CreateKey();

        public abstract bool SupportsOptimisticPreAuthentication { get; }

        public virtual void TransformKdcReq(KrbKdcReq req)
        {
            var ts = KrbPaEncTsEnc.Now();

            var tsEncoded = ts.Encode();

            var padata = req.PaData.ToList();

            var key = CreateKey();

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
            foreach (var padata in preauth)
            {
                if (padata.Type != PaDataType.PA_ETYPE_INFO2)
                {
                    continue;
                }

                var etypeInfo = padata.DecodeETypeInfo2();

                Salts = etypeInfo.Select(e => new KeyValuePair<EncryptionType, string>(e.EType, e.Salt));
            }
        }

        protected static void TrySplitUserNameDomain(string original, out string username, ref string domain)
        {
            username = original;

            var index = original.IndexOf('@');

            if (index > 0)
            {
                username = original.Substring(0, index);

                if (string.IsNullOrWhiteSpace(domain))
                {
                    domain = original.Substring(index + 1, original.Length - username.Length - 1);
                }
            }
        }

        public virtual void Validate()
        {
            if (string.IsNullOrWhiteSpace(UserName))
            {
                throw new ArgumentException("UserName cannot be null or empty", nameof(UserName));
            }

            if (string.IsNullOrWhiteSpace(Domain))
            {
                throw new ArgumentException("Domain cannot be null or empty", nameof(Domain));
            }
        }

        public virtual T DecryptKdcRep<T>(KrbKdcRep kdcRep, KeyUsage keyUsage, Func<ReadOnlyMemory<byte>, T> func)
        {
            return kdcRep.EncPart.Decrypt(
                CreateKey(),
                keyUsage,
                func
            );
        }
    }
}
