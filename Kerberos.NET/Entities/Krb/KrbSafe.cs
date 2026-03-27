// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbSafe
    {
        /// <summary>
        /// Create a KRB-SAFE message that integrity-protects the provided data.
        /// </summary>
        public static KrbSafe Create(
            ReadOnlyMemory<byte> userData,
            KerberosKey key,
            KrbHostAddress senderAddress,
            KrbHostAddress recipientAddress = null,
            int? sequenceNumber = null)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var body = new KrbSafeBody
            {
                UserData = userData,
                Timestamp = DateTimeOffset.UtcNow,
                Usec = 0,
                SeqNumber = sequenceNumber,
                SAddress = senderAddress,
                RAddress = recipientAddress
            };

            var encodedBody = body.Encode();

            var checksum = KrbChecksum.Create(encodedBody, key, KeyUsage.KrbSafeChecksum);

            return new KrbSafe
            {
                ProtocolVersionNumber = 5,
                MessageType = MessageType.KRB_SAFE,
                SafeBody = body,
                Checksum = checksum
            };
        }

        /// <summary>
        /// Verify the integrity of a KRB-SAFE message and return the user data.
        /// </summary>
        public ReadOnlyMemory<byte> Verify(KerberosKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            if (this.SafeBody == null)
            {
                throw new InvalidOperationException("SafeBody is null");
            }

            var encodedBody = this.SafeBody.Encode();

            var checksumValidator = CryptoService.CreateChecksum(
                this.Checksum.Type,
                this.Checksum.Checksum,
                encodedBody
            );

            checksumValidator.Usage = KeyUsage.KrbSafeChecksum;
            checksumValidator.Validate(key);

            return this.SafeBody.UserData;
        }
    }
}
