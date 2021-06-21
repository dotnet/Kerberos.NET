// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Crypto
{
    [DebuggerDisplay("{EncryptionType} {SaltFormat} {Version} ({Salt})")]
    public class KerberosKey
    {
        private readonly ConcurrentDictionary<EncryptionType, ReadOnlyMemory<byte>> keyCache
            = new ConcurrentDictionary<EncryptionType, ReadOnlyMemory<byte>>();

        private readonly ConcurrentDictionary<string, ReadOnlyMemory<byte>> derivedKeyCache
            = new ConcurrentDictionary<string, ReadOnlyMemory<byte>>();

        private readonly byte[] key;

        private byte[] saltBytes;

        private string salt;

        private byte[] passwordBytes;

        public KerberosKey(KrbEncryptionKey key)
            : this(key: key?.KeyValue.ToArray(), etype: key.EType)
        {
        }

        public KerberosKey(
            string password,
            PrincipalName principalName = null,
            string host = null,
            string salt = null,
            byte[] saltBytes = null,
            EncryptionType etype = 0,
            SaltType saltType = SaltType.ActiveDirectoryService,
            byte[] iterationParams = null,
            int? kvno = null
        )
            : this(null, password, null, principalName, host, salt, saltBytes, etype, saltType, iterationParams, kvno)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password));
            }
        }

        public KerberosKey(
            byte[] key = null,
            byte[] password = null,
            PrincipalName principal = null,
            string host = null,
            string salt = null,
            byte[] saltBytes = null,
            EncryptionType etype = 0,
            SaltType saltType = SaltType.ActiveDirectoryService,
            byte[] iterationParams = null,
            int? kvno = null
        )
            : this(key, null, password, principal, host, salt, saltBytes, etype, saltType, iterationParams, kvno)
        {
            if (key == null && password == null)
            {
                throw new ArgumentException("Either a key or password must be provided");
            }
        }

        private KerberosKey(
            byte[] key,
            string password,
            byte[] passwordBytes = null,
            PrincipalName principalName = null,
            string host = null,
            string salt = null,
            byte[] saltBytes = null,
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
            this.saltBytes = saltBytes;
            this.EncryptionType = etype;
            this.SaltFormat = saltFormat;
            this.IterationParameter = iterationParams;
            this.Version = kvno;
        }

        public KeyUsage? Usage { get; set; }

        public EncryptionType EncryptionType { get; }

        public string Host { get; }

        public PrincipalName PrincipalName { get; }

        public int? Version { get; }

        public string Password { get; }

        public ReadOnlyMemory<byte> IterationParameter { get; }

        public SaltType SaltFormat { get; }

        public bool RequiresDerivation => this.key == null || this.key.Length <= 0;

        public ReadOnlyMemory<byte> SaltBytes
        {
            get
            {
                if (this.saltBytes == null && !string.IsNullOrEmpty(this.Salt))
                {
                    this.saltBytes = KerberosConstants.UnicodeStringToUtf8(this.Salt).ToArray();
                }

                return this.saltBytes;
            }
        }

        public string Salt
        {
            get
            {
                if (string.IsNullOrWhiteSpace(this.salt))
                {
                    if (IsAes(this.EncryptionType))
                    {
                        var sb = new StringBuilder();

                        AesSalts.GenerateSalt(this, sb);

                        this.salt = sb.ToString();
                    }
                }

                return this.salt;
            }
        }

        public ReadOnlyMemory<byte> PasswordBytes
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(this.Password))
                {
                    this.passwordBytes = Encoding.Unicode.GetBytes(this.Password);
                }

                return this.passwordBytes;
            }
        }

        public static KerberosKey DeriveFromKeyId(
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
                principalName: name?.ToKeyPrincipal()
            );

            return kerbKey;
        }

        public static ReadOnlyMemory<byte> GenerateFile(
            string password,
            Guid saltGuid,
            KrbPrincipalName name,
            EncryptionType etype = EncryptionType.AES256_CTS_HMAC_SHA1_96
        )
        {
            var kerbKey = DeriveFromKeyId(password, saltGuid, name, etype);

            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                var keytab = new KeyTable(kerbKey);

                keytab.Write(writer);

                return stream.ToArray();
            }
        }

        public ReadOnlyMemory<byte> GetKey(KerberosCryptoTransformer transformer = null)
        {
            if (!this.RequiresDerivation)
            {
                return this.key;
            }

            if (transformer == null)
            {
                transformer = CryptoService.CreateTransform(this.EncryptionType);
            }

            if (transformer == null)
            {
                throw new NotSupportedException($"Unknown EType: {this.EncryptionType}");
            }

            return this.keyCache.GetOrAdd(transformer.EncryptionType, etype => transformer.String2Key(this));
        }

        public override bool Equals(object obj)
        {
            if (obj is not KerberosKey key)
            {
                return base.Equals(obj);
            }

            return KerberosCryptoTransformer.AreEqualSlow(this.GetKey().Span, key.GetKey().Span) &&
                   this.EncryptionType == key.EncryptionType;
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(
                this.Version ?? 0,
                this.key ?? Array.Empty<byte>(),
                this.PasswordBytes,
                this.Host ?? string.Empty,
                this.PrincipalName ?? new PrincipalName()
            );
        }

        internal ReadOnlyMemory<byte> GetOrDeriveKey(
            KerberosCryptoTransformer transformer,
            string cacheKey,
            Func<ReadOnlyMemory<byte>, ReadOnlyMemory<byte>> dk
        )
        {
            var derived = this.derivedKeyCache.GetOrAdd(cacheKey, str => dk(this.GetKey(transformer)));

            return derived;
        }

        private static string NormalizeGuid(Guid saltGuid)
        {
            // lowercase, no dashes
            // e.g. 0aa29dcb-3a9b-413f-aee2-8df91fd1118e => 0aa29dcb3a9b413faee28df91fd1118e

            return saltGuid.ToString("n");
        }

        private static bool IsAes(EncryptionType etype)
        {
            return etype >= EncryptionType.AES128_CTS_HMAC_SHA1_96 &&
                   etype <= EncryptionType.AES256_CTS_HMAC_SHA384_192;
        }
    }
}
