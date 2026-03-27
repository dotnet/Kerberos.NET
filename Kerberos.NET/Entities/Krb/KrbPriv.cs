// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbPriv
    {
        public static KrbPriv Create(KerberosKey key, KrbEncKrbPrivPart krbPrivEncPartUnencrypted)
        {
            return new KrbPriv
            {
                ProtocolVersionNumber = 5,
                MessageType = MessageType.KRB_PRIV,
                EncPart = KrbEncryptedData.Encrypt(
                            data: krbPrivEncPartUnencrypted.EncodeApplication(),
                            key: key,
                            usage: KeyUsage.EncKrbPrivPart)
            };
        }

        /// <summary>
        /// Decrypt the KRB-PRIV message and return the enclosed private part.
        /// </summary>
        public KrbEncKrbPrivPart Decrypt(KerberosKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return this.EncPart.Decrypt(
                key,
                KeyUsage.EncKrbPrivPart,
                b => KrbEncKrbPrivPart.DecodeApplication(b)
            );
        }
    }
}
