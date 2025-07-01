// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Client
{
    public class ApplicationSessionContext
    {
        public KrbApReq ApReq { get; set; }

        public KrbEncryptionKey SessionKey { get; set; }

        public KrbEncryptionKey ServiceTicketSessionKey { get; set; }

        public KrbEncryptionKey ClientSubSessionKey { get; set; }

        public int? SequenceNumber { get; set; }

        public int CuSec { get; set; }

        public DateTimeOffset CTime { get; set; }

        public KrbEncryptionKey AuthenticateServiceResponse(string asRepEncoded)
        {
            return AuthenticateServiceResponse(Convert.FromBase64String(asRepEncoded));
        }

        public KrbEncryptionKey AuthenticateServiceResponse(ReadOnlyMemory<byte> apRepBytes)
        {
            var apRep = KrbApRep.DecodeApplication(apRepBytes);

            var decrypted = new DecryptedKrbApRep(apRep)
            {
                CTime = this.CTime,
                CuSec = this.CuSec,
                SequenceNumber = this.SequenceNumber
            };

            DecryptApRep(decrypted);

            decrypted.Validate(ValidationActions.TokenWindow);

            return decrypted.Response.SubSessionKey ?? this.SessionKey;
        }

        private void DecryptApRep(DecryptedKrbApRep decrypted)
        {
            foreach (var key in new[]
            {
                this.SessionKey,
                this.ServiceTicketSessionKey,
                this.ClientSubSessionKey,
            })
            {
                if (key == null)
                {
                    continue;
                }

                try
                {
                    decrypted.Decrypt(key.AsKey());
                    return;
                }
                catch (Exception)
                {
                    // Not this key, continue to the next one
                }
            }

            throw new InvalidOperationException("Failed to decrypt AP_REP with any of the provided keys.");
        }
    }
}
