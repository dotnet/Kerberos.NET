using Kerberos.NET.Crypto;
using System;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public partial class KrbKdcReq
    {
        public KrbKdcReq()
        {
            ProtocolVersionNumber = 5;
        }

        public DateTimeOffset DecryptTimestamp(KerberosKey key)
        {
            var timestampPaData = PaData.FirstOrDefault(p => p.Type == PaDataType.PA_ENC_TIMESTAMP);

            if (timestampPaData == null)
            {
                return DateTimeOffset.MinValue;
            }

            var encryptedTimestamp = KrbEncryptedData.Decode(timestampPaData.Value);

            var tsEnc = encryptedTimestamp.Decrypt(key, KeyUsage.PaEncTs, d => KrbPaEncTsEnc.Decode(d));

            var timestamp = tsEnc.PaTimestamp;

            if (tsEnc.PaUSec > 0)
            {
                timestamp = timestamp.AddTicks(tsEnc.PaUSec.Value / 10);
            }

            return timestamp;
        }
    }
}
