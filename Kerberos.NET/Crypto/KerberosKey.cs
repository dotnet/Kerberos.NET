using Kerberos.NET.Crypto.AES;
using Kerberos.NET.Entities;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;

namespace Kerberos.NET.Crypto
{
    public class KerberosKey
    {
        public KerberosKey(KrbEncryptionKey key)
            : this(key: key.KeyValue.ToArray(), etype: key.EType)
        { }

        public KerberosKey(
            string password,
            PrincipalName principalName = null,
            string host = null,
            string salt = null,
            EncryptionType etype = 0,
            SaltType saltType = SaltType.ActiveDirectoryService,
            byte[] iterationParams = null,
            int? kvno = null
        ) : this(null, password, null, principalName, host, salt, etype, saltType, iterationParams, kvno)
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
            byte[] iterationParams = null,
            int? kvno = null
            ) : this(key, null, password, principal, host, salt, etype, saltType, iterationParams, kvno)
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
            byte[] iterationParams = null,
            int? kvno = null
        )
        {
            this.key = key;
            this.Password = password;
            this.passwordBytes = passwordBytes;
            this.PrincipalName = principalName;
            this.Host = host;
            this.salt = salt;
            this.EncryptionType = etype;
            this.SaltFormat = saltFormat;
            IterationParameter = iterationParams;
            this.Version = kvno;
        }

        private readonly ConcurrentDictionary<string, ReadOnlyMemory<byte>> DerivedKeyCache
            = new ConcurrentDictionary<string, ReadOnlyMemory<byte>>();

        public KeyUsage? Usage { get; set; }

        public static ReadOnlyMemory<byte> GenerateFile(
            string password,
            Guid saltGuid,
            KrbPrincipalName name,
            EncryptionType etype = EncryptionType.AES256_CTS_HMAC_SHA1_96
        )
        {
            var salt = NormalizeGuid(saltGuid);

            var kerbKey = new KerberosKey(
                password: password,
                etype: etype,
                salt: salt,
                principalName: name.ToKeyPrincipal()
            );

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                var keytab = new KeyTable(kerbKey);

                keytab.Write(writer);

                return stream.ToArray();
            }
        }

        private static string NormalizeGuid(Guid saltGuid)
        {
            // lowercase, no dashes
            // e.g. 0aa29dcb-3a9b-413f-aee2-8df91fd1118e => 0aa29dcb3a9b413faee28df91fd1118e

            return saltGuid.ToString("n");
        }

        internal ReadOnlyMemory<byte> GetOrDeriveKey(
            KerberosCryptoTransformer transformer,
            string cacheKey,
            Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> dk
        )
        {
            var derived = DerivedKeyCache.GetOrAdd(cacheKey, str => dk(GetKey(transformer)));

            return derived;
        }

        private string salt;

        public EncryptionType EncryptionType { get; }

        public string Host { get; }

        public PrincipalName PrincipalName { get; }

        public int? Version { get; }

        public string Salt
        {
            get
            {
                if (string.IsNullOrWhiteSpace(salt))
                {
                    if (EncryptionType == EncryptionType.AES128_CTS_HMAC_SHA1_96 ||
                        EncryptionType == EncryptionType.AES256_CTS_HMAC_SHA1_96)
                    {
                        var sb = new StringBuilder();

                        AesSalts.GenerateSalt(this, sb);

                        salt = sb.ToString();
                    }
                }

                return salt;
            }
        }

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

        private readonly object _keyLock = new object();

        private ReadOnlyMemory<byte> keyCache = null;

        public ReadOnlyMemory<byte> GetKey(KerberosCryptoTransformer transformer = null)
        {
            if (key != null && key.Length > 0)
            {
                return key;
            }

            if (transformer == null)
            {
                transformer = CryptoService.CreateTransform(EncryptionType);
            }

            if (transformer == null)
            {
                throw new NotSupportedException();
            }

            if (keyCache.Length <= 0)
            {
                lock (_keyLock)
                {
                    if (keyCache.Length <= 0)
                    {
                        keyCache = transformer.String2Key(this);
                    }
                }
            }

            return keyCache;
        }

        public override bool Equals(object obj)
        {
            var key = obj as KerberosKey;

            if (key == null)
            {
                return base.Equals(obj);
            }

            return KerberosCryptoTransformer.AreEqualSlow(this.GetKey().Span, key.GetKey().Span) &&
                   this.EncryptionType == key.EncryptionType;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(
                Version ?? 0, 
                key ?? Array.Empty<byte>(), 
                PasswordBytes, 
                Host ?? "", 
                PrincipalName ?? new PrincipalName()
            );
        }
    }
}
