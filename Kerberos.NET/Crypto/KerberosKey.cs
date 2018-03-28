using Kerberos.NET.Entities;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public class KerberosKey
    {
        public KerberosKey(string password, PrincipalName principalName = null, string host = null)
            : this(null, password, null, principalName, host)
        {
        }

        private KerberosKey(byte[] key, string password, byte[] passwordBytes = null, PrincipalName principalName = null, string host = null)
        {
            this.key = key;
            this.password = password;
            this.passwordBytes = passwordBytes;
            this.principalName = principalName;
            this.host = host;
        }

        public KerberosKey(byte[] key = null, byte[] password = null, string host = null)
            : this(key, null, password, null, host)
        {
        }

        private readonly byte[] key;
        private readonly string password;
        private readonly string host;

        private readonly PrincipalName principalName;

        public string Password { get { return password; } }

        private byte[] passwordBytes;

        public byte[] PasswordBytes
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Password))
                {
                    passwordBytes = Encoding.Unicode.GetBytes(Password);
                }

                return passwordBytes;
            }
        }

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
            if (passwordBytes != null && passwordBytes.Length > 0)
            {
                return new KerberosKey(null, password, passwordBytes, sName, host);
            }

            return new KerberosKey(key, password, null, sName, host);
        }
    }
}
