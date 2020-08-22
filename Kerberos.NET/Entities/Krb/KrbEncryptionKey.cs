// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{EType} {Usage} [{KeyValue.Length}]")]
    public partial class KrbEncryptionKey
    {
        public KerberosKey AsKey(KeyUsage? usage = null)
        {
            return new KerberosKey(this) { Usage = usage };
        }

        public KeyUsage Usage { get; set; }

        public static KrbEncryptionKey Generate(EncryptionType type)
        {
            var crypto = CryptoService.CreateTransform(type);

            if (crypto == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {type}");
            }

            return new KrbEncryptionKey
            {
                EType = type,
                KeyValue = crypto.GenerateKey()
            };
        }
    }
}