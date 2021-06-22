// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{ErrorCode} {EText}")]
    public partial class KrbError
    {
        public KrbError()
        {
            this.ProtocolVersionNumber = 5;
            this.MessageType = MessageType.KRB_ERROR;
        }

        private static readonly Asn1Tag KrbErrorTag = new Asn1Tag(TagClass.Application, 30);

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(KrbErrorTag);
        }

        public void StampServerTime()
        {
            Now(out DateTimeOffset stime, out int usec);

            this.STime = stime;
            this.Cusec = usec;
        }

        public IEnumerable<KrbPaData> DecodePreAuthentication()
        {
            if (this.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
            {
                throw new InvalidOperationException($"Cannot parse Pre-Auth PaData because error is {this.ErrorCode}");
            }

            if (!this.EData.HasValue)
            {
                throw new InvalidOperationException("Pre-Auth data isn't present in EData");
            }

            var krbMethod = KrbMethodData.Decode(this.EData.Value, AsnEncodingRules.DER);

            return krbMethod.MethodData;
        }
    }
}
