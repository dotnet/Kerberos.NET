using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public class DecryptedKrbApRep : DecryptedKrbMessage
    {
        private readonly KrbApRep response;

        public KrbEncApRepPart Response { get; set; }

        public DateTimeOffset CTime { get; internal set; }

        public int CuSec { get; internal set; }

        public int? SequenceNumber { get; internal set; }

        public DecryptedKrbApRep(KrbApRep response)
        {
            this.response = response;
        }

        public override void Decrypt(KerberosKey key)
        {
            Response = response.EncryptedPart.Decrypt(
                key,
                KeyUsage.EncApRepPart,
                data => KrbEncApRepPart.DecodeApplication(data)
            );
        }

        public override void Validate(ValidationActions validation)
        {
            var now = Now();

            var ctime = Response.CTime.AddTicks(Response.CuSec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                ValidateTicketSkew(now, Skew, ctime);
            }

            if (KerberosConstants.TimeEquals(CTime, Response.CTime))
            {
                throw new KerberosValidationException(
                    $"CTime does not match. Sent: {CTime.Ticks}; Received: {Response.CTime.Ticks}"
                );
            }

            if (CuSec != Response.CuSec)
            {
                throw new KerberosValidationException(
                    $"CuSec does not match. Sent: {CuSec}; Received: {Response.CuSec}"
                );
            }

            if (SequenceNumber != Response.SequenceNumber)
            {
                throw new KerberosValidationException(
                    $"SequenceNumber does not match. Sent: {SequenceNumber}; Received: {Response.SequenceNumber}"
                );
            }
        }
    }
}
