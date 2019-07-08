using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Linq;

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

            UserName = username;
            this.password = password;

            if (!string.IsNullOrWhiteSpace(domain))
            {
                Domain = domain.ToUpperInvariant();
            }
        }

        public override void Validate()
        {
            base.Validate();

            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
            }
        }

        public override KerberosKey CreateKey()
        {
            var principalName = new PrincipalName(PrincipalNameType.NT_PRINCIPAL, Domain, new[] { UserName });

            var etype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
            var salt = "";

            if (Salts != null && Salts.Count() > 0)
            {
                var kv = Salts.ElementAt(0);

                etype = kv.Key;
                salt = kv.Value;
            }

            var key = new KerberosKey(
                password,
                principalName: principalName,
                etype: etype,
                saltType: SaltType.ActiveDirectoryUser,
                salt: salt
            );

            return key;
        }
    }
}
