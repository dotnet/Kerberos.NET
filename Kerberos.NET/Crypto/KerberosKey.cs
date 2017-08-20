using Kerberos.NET.Entities;

namespace Kerberos.NET.Crypto
{
    public class KerberosKey
    {
        public KerberosKey(string password, PrincipalName principalName = null, string host = null)
            : this(null, password, principalName, host)
        {
        }

        private KerberosKey(byte[] key, string password, PrincipalName principalName = null, string host = null)
        {
            this.key = key;
            this.password = password;
            this.principalName = principalName;
            this.host = host;
        }

        public KerberosKey(byte[] key)
            : this(key, null, null, null)
        {
        }

        private readonly byte[] key;
        private readonly string password;
        private readonly string host;

        private readonly PrincipalName principalName;

        public string Password { get { return password; } }

        public string Host { get { return host; } }

        public PrincipalName PrincipalName { get { return principalName; } }

        public byte[] GetKey(IEncryptor encryptor)
        {
            if (key != null && key.Length > 0)
            {
                return key;
            }

            return encryptor.String2Key(this);
        }

        internal KerberosKey WithPrincipalName(PrincipalName sName)
        {
            return new KerberosKey(key, password, sName, host);
        }
    }
}
