// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbChecksum
    {
        internal const ChecksumType ChecksumContainsDelegationType = (ChecksumType)0x8003;

        public DelegationInfo DecodeDelegation()
        {
            if (this.Type != ChecksumContainsDelegationType)
            {
                throw new InvalidOperationException($"Cannot decode delegation ticket in checksum because type is {this.Type}");
            }

            return new DelegationInfo().Decode(this.Checksum);
        }

        public static KrbChecksum EncodeDelegationChecksum(DelegationInfo deleg)
        {
            if (deleg == null)
            {
                throw new ArgumentNullException(nameof(deleg));
            }

            return new KrbChecksum
            {
                Type = ChecksumContainsDelegationType,
                Checksum = deleg.Encode()
            };
        }

        public static KrbChecksum Create(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage ku, ChecksumType type = 0)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (type == 0)
            {
                type = CryptoService.ConvertType(key.EncryptionType);
            }

            var checksum = CryptoService.CreateChecksum(type, signatureData: data);

            if (checksum == null)
            {
                throw new InvalidOperationException($"CryptoService couldn't create a transform for type {type}");
            }

            checksum.Usage = ku;

            checksum.Sign(key);

            return new KrbChecksum
            {
                Checksum = checksum.Signature,
                Type = type
            };
        }
    }
}