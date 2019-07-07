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
            string host = null,
            string salt = null,
            EncryptionType etype = 0,
            SaltType saltType = SaltType.ActiveDirectoryService,
            byte[] iterationParams = null
        ) : this(null, password, null, principalName, host, salt, etype, saltType, iterationParams)
        {
        }

        public KerberosKey(
            byte[] key = null,
            byte[] password = null,
            PrincipalName principal = null,
            string host = null,
            string salt = null,
            EncryptionType etype = 0,
            SaltType saltType = SaltType.ActiveDirectoryService,
            byte[] iterationParams = null
            ) : this(key, null, password, principal, host, salt, etype, saltType, iterationParams)
        {
        }

        private KerberosKey(
            byte[] key,
            string password,
            byte[] passwordBytes = null,
            PrincipalName principalName = null,
            string host = null,
            string salt = null,
            EncryptionType etype = 0,
            SaltType saltFormat = SaltType.ActiveDirectoryService,
            byte[] iterationParams = null
        )
        {
            this.key = key;
            this.Password = password;
            this.passwordBytes = passwordBytes;
            this.PrincipalName = principalName;
            this.Host = host;
            this.Salt = salt;
            this.EncryptionType = etype;
            this.SaltFormat = saltFormat;
            IterationParameter = iterationParams;
        }

        public EncryptionType EncryptionType { get; }

        public string Host { get; }

        public PrincipalName PrincipalName { get; }

        public string Salt { get; }

        private readonly byte[] key;

        public string Password { get; }

        public byte[] IterationParameter { get; }

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

        public SaltType SaltFormat { get; }

        public int? Version { get; set; }

        public byte[] GetKey(KerberosCryptoTransformer transformer = null)
        {
            if (key != null && key.Length > 0)
            {
                return key;
            }

            if (transformer == null)
            {
                transformer = CryptographyService.CreateTransform(EncryptionType);
            }

            if (transformer == null)
            {
                throw new NotSupportedException();
            }

            return transformer.String2Key(this);
        }

        public override bool Equals(object obj)
        {
            var key = obj as KerberosKey;

            if (key == null)
            {
                return base.Equals(obj);
            }

            return KerberosCryptoTransformer.AreEqualSlow(this.GetKey(), key.GetKey()) &&
                   this.EncryptionType == key.EncryptionType;
        }

        public override int GetHashCode()
        {
            return base.GetHashCode() ^
                  (key ?? new byte[0]).GetHashCode() ^
                   PasswordBytes.GetHashCode() ^
                  (Host ?? "").GetHashCode() ^
                  (PrincipalName ?? new PrincipalName()).GetHashCode();
        }
    }
}
