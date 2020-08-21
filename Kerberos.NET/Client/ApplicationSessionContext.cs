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

        public int? SequenceNumber { get; set; }

        public int CuSec { get; set; }

        public DateTimeOffset CTime { get; set; }

        public KrbEncryptionKey AuthenticateServiceResponse(string asRepEncoded)
        {
            var apRep = KrbApRep.DecodeApplication(Convert.FromBase64String(asRepEncoded));

            var decrypted = new DecryptedKrbApRep(apRep) { CTime = this.CTime, CuSec = this.CuSec, SequenceNumber = this.SequenceNumber };

            decrypted.Decrypt(this.SessionKey.AsKey());

            decrypted.Validate(ValidationActions.TokenWindow);

            return decrypted.Response.SubSessionKey ?? this.SessionKey;
        }
    }
}