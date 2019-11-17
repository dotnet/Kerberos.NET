using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Linq;

namespace Kerberos.NET.Credentials
{
    public class KeytabCredential : KerberosCredential
    {
        private readonly KeyTable keytab;

        public KeytabCredential(string username, KeyTable keytab, string domain = null)
        {
            TrySplitUserNameDomain(username, out username, ref domain);

            UserName = username;

            this.keytab = keytab ?? throw new ArgumentNullException(nameof(keytab));

            if (!string.IsNullOrWhiteSpace(domain))
            {
                Domain = domain.ToUpperInvariant();
            }
        }

        public override KerberosKey CreateKey()
        {
            Validate();

            var principalName = KrbPrincipalName.FromString(UserName);

            if (Salts == null || !Salts.Any())
            {
                return keytab.GetKey(EncryptionType.RC4_HMAC_NT, principalName);
            }

            foreach (var salt in Salts)
            {
                var key = keytab.GetKey(salt.Key, principalName);

                if (key != null)
                {
                    return key;
                }
            }

            return null;
        }
    }
}
