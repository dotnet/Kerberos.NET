// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Client
{
    /// <summary>
    /// Provides application-level message protection using the Kerberos KRB-SAFE
    /// (integrity protection) and KRB-PRIV (confidentiality protection) message types
    /// as defined in RFC 4120 sections 3.4 and 3.5.
    /// </summary>
    public class KerberosMessageService
    {
        private readonly KerberosKey sessionKey;
        private readonly KrbHostAddress localAddress;
        private readonly KrbHostAddress remoteAddress;
        private int sequenceNumber;

        public KerberosMessageService(
            KerberosKey sessionKey,
            KrbHostAddress localAddress = null,
            KrbHostAddress remoteAddress = null,
            int initialSequenceNumber = 0)
        {
            this.sessionKey = sessionKey ?? throw new ArgumentNullException(nameof(sessionKey));
            this.localAddress = localAddress;
            this.remoteAddress = remoteAddress;
            this.sequenceNumber = initialSequenceNumber;
        }

        /// <summary>
        /// Create a KRB-SAFE message providing integrity protection for the data.
        /// </summary>
        public KrbSafe MakeSafe(ReadOnlyMemory<byte> data)
        {
            return KrbSafe.Create(
                data,
                this.sessionKey,
                this.localAddress,
                this.remoteAddress,
                this.sequenceNumber++);
        }

        /// <summary>
        /// Verify a KRB-SAFE message and return the protected data.
        /// </summary>
        public ReadOnlyMemory<byte> VerifySafe(KrbSafe safe)
        {
            if (safe == null)
            {
                throw new ArgumentNullException(nameof(safe));
            }

            return safe.Verify(this.sessionKey);
        }

        /// <summary>
        /// Create a KRB-PRIV message providing confidentiality protection for the data.
        /// </summary>
        public KrbPriv MakePriv(ReadOnlyMemory<byte> data)
        {
            var privPart = new KrbEncKrbPrivPart
            {
                UserData = data,
                Timestamp = DateTimeOffset.UtcNow,
                Usec = 0,
                SeqNumber = this.sequenceNumber++,
                SAddress = this.localAddress,
                RAddress = this.remoteAddress
            };

            return KrbPriv.Create(this.sessionKey, privPart);
        }

        /// <summary>
        /// Decrypt a KRB-PRIV message and return the protected data.
        /// </summary>
        public ReadOnlyMemory<byte> DecryptPriv(KrbPriv priv)
        {
            if (priv == null)
            {
                throw new ArgumentNullException(nameof(priv));
            }

            var decrypted = priv.Decrypt(this.sessionKey);

            return decrypted.UserData;
        }
    }
}
