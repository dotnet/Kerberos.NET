// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbKdcReq
    {
        public KrbKdcReq()
        {
            this.ProtocolVersionNumber = 5;
        }

        public DateTimeOffset DecryptTimestamp(KerberosKey key) => DecryptTimestamp(key, out _);

        public DateTimeOffset DecryptTimestamp(KerberosKey key, out EncryptionType etype)
        {
            var timestampPaData = this.PaData.FirstOrDefault(p => p.Type == PaDataType.PA_ENC_TIMESTAMP);

            if (timestampPaData == null)
            {
                etype = EncryptionType.NULL;
                return DateTimeOffset.MinValue;
            }

            var encryptedTimestamp = KrbEncryptedData.Decode(timestampPaData.Value);

            var tsEnc = encryptedTimestamp.Decrypt(key, KeyUsage.PaEncTs, d => KrbPaEncTsEnc.Decode(d));

            var timestamp = tsEnc.PaTimestamp;

            if (tsEnc.PaUSec > 0)
            {
                timestamp = timestamp.AddTicks(tsEnc.PaUSec.Value / 10);
            }

            etype = encryptedTimestamp.EType;

            return timestamp;
        }
    }
}
