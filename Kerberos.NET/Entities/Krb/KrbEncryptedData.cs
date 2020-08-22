// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncryptedData
    {
        public T Decrypt<T>(KerberosKey key, KeyUsage usage, Func<ReadOnlyMemory<byte>, T> func)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (func == null)
            {
                throw new ArgumentNullException(nameof(func));
            }

            if (!key.RequiresDerivation && key.EncryptionType != this.EType)
            {
                throw new InvalidOperationException($"Key EType {key.EncryptionType} must match the encrypted data EType {this.EType}");
            }

            var crypto = CryptoService.CreateTransform(this.EType);

            if (crypto == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {key.EncryptionType}");
            }

            var decrypted = crypto.Decrypt(this.Cipher, key, usage);

            return func(decrypted);
        }

        public static KrbEncryptedData Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var crypto = CryptoService.CreateTransform(key.EncryptionType);

            if (crypto == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {key.EncryptionType}");
            }

            ReadOnlyMemory<byte> cipher = crypto.Encrypt(data, key, usage);

            return new KrbEncryptedData
            {
                Cipher = cipher,
                EType = key.EncryptionType,
                KeyVersionNumber = key.Version
            };
        }
    }
}