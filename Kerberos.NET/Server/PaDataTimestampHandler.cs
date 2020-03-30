using System;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Server
{
    public class PaDataTimestampHandler : KdcPreAuthenticationHandlerBase
    {
        public PaDataTimestampHandler(IRealmService service)
            : base(service)
        {
        }

        public override KrbPaData Validate(KrbKdcReq asReq, PreAuthenticationContext preauth)
        {
            if (preauth.PreAuthenticationSatisfied)
            {
                return null;
            }

            var principal = preauth.Principal;
            var cred = principal.RetrieveLongTermCredential();

            var timestamp = asReq.DecryptTimestamp(cred);

            if (timestamp == DateTimeOffset.MinValue)
            {
                return new KrbPaData
                {
                    Type = PaDataType.PA_ENC_TIMESTAMP
                };
            }

            var skew = Service.Settings.MaximumSkew;

            DateTimeOffset now = Service.Now();

            if (Abs(now - timestamp) > skew)
            {
                throw new KerberosValidationException(
                    $"Timestamp window is greater than allowed skew. Start: {timestamp}; End: {now}; Skew: {skew}"
                );
            }

            preauth.EncryptedPartKey = cred;
            preauth.ClientAuthority = PaDataType.PA_ENC_TIMESTAMP;

            return null;
        }

        private static TimeSpan Abs(TimeSpan timeSpan)
        {
            if (timeSpan < TimeSpan.Zero)
            {
                return -timeSpan;
            }

            return timeSpan;
        }
    }
}
