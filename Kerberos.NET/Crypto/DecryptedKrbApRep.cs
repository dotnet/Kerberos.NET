// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Crypto
{
    public class DecryptedKrbApRep : DecryptedKrbMessage
    {
        private readonly KrbApRep response;

        public KrbEncApRepPart Response { get; set; }

        public DateTimeOffset CTime { get; set; }

        public int CuSec { get; set; }

        public int? SequenceNumber { get; set; }

        public DecryptedKrbApRep(KrbApRep response)
        {
            this.response = response ?? throw new ArgumentNullException(nameof(response));
        }

        public override void Decrypt(KerberosKey key)
        {
            this.Response = this.response.EncryptedPart.Decrypt(
                key,
                KeyUsage.EncApRepPart,
                data => KrbEncApRepPart.DecodeApplication(data)
            );
        }

        public override void Validate(ValidationActions validation)
        {
            var now = this.Now();

            var ctime = this.Response.CTime.AddTicks(this.Response.CuSec / 10);

            if (validation.HasFlag(ValidationActions.TokenWindow))
            {
                this.ValidateTicketSkew(now, this.Skew, ctime);
            }

            if (TimeEquals(this.CTime, this.Response.CTime))
            {
                throw new KerberosValidationException(
                    $"CTime does not match. Sent: {this.CTime.Ticks}; Received: {this.Response.CTime.Ticks}",
                    nameof(this.CTime)
                );
            }

            if (this.CuSec != this.Response.CuSec)
            {
                throw new KerberosValidationException(
                    $"CuSec does not match. Sent: {this.CuSec}; Received: {this.Response.CuSec}",
                    nameof(this.CuSec)
                );
            }

            if (this.SequenceNumber != this.Response.SequenceNumber)
            {
                throw new KerberosValidationException(
                    $"SequenceNumber does not match. Sent: {this.SequenceNumber}; Received: {this.Response.SequenceNumber}",
                    nameof(this.SequenceNumber)
                );
            }
        }
    }
}
