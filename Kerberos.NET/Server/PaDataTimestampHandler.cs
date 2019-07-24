using Kerberos.NET.Entities;
using System;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public class PaDataTimestampHandler : KdcPreAuthenticationHandlerBase
    {
        public PaDataTimestampHandler(IRealmService service)
            : base(service)
        {
        }

        public override async Task<KrbPaData> Validate(KrbKdcReq asReq, IKerberosPrincipal principal)
        {
            var timestamp = asReq.DecryptTimestamp(await principal.RetrieveLongTermCredential());

            if (timestamp == DateTimeOffset.MinValue)
            {
                return new KrbPaData
                {
                    Type = PaDataType.PA_ENC_TIMESTAMP
                };
            }

            var skew = Service.Settings.MaximumSkew;

            DateTimeOffset now = Service.Now();

            if ((now - timestamp) > skew)
            {
                throw new KerberosValidationException(
                    $"Timestamp window is greater than allowed skew. Start: {timestamp}; End: {now}; Skew: {skew}"
                );
            }

            return null;
        }
    }
}