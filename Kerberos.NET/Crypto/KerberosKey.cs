using Kerberos.NET.Entities;
using System;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public class KerberosKey
    {
        public KerberosKey(
            string password,
            PrincipalName principalName = null,
            string host = null
        ) : this(null, password, null, principalName, host)
        {
        }

        private KerberosKey(
            byte[] key,
            string password,
            byte[] passwordBytes = null,
            PrincipalName principalName = null,
            string host = null)
        {
            this.key = key;
            this.Password = password;
            this.passwordBytes = passwordBytes;
            this.PrincipalName = principalName;
            this.Host = host;
        }

        public KerberosKey(byte[] key = null, byte[] password = null, string host = null)
            : this(key, null, password, null, host)
        {
        }

        private readonly byte[] key;

        public string Password { get; }

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

        public string Host { get; }

        public PrincipalName PrincipalName { get; }

        public byte[] GetKey(IEncryptor encryptor)
        {
            if (key != null && key.Length > 0)
            {
                return key;
            }

            if (encryptor == null)
            {
                throw new NotSupportedException();
            }

            return encryptor.String2Key(this);
        }

        internal KerberosKey WithPrincipalName(PrincipalName sName)
        {
            if (passwordBytes != null && passwordBytes.Length > 0)
            {
                return new KerberosKey(null, Password, passwordBytes, sName, Host);
            }

            return new KerberosKey(key, Password, null, sName, Host);
        }
    }
}
