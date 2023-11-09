// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public static class KrbApChoice
    {
        private static readonly Asn1Tag KrbApReqTag = new(TagClass.Application, 14);

        private static readonly Asn1Tag KrbApRepTag = new(TagClass.Application, 15);

        public static bool CanDecode(ReadOnlyMemory<byte> encoded, out MessageType type)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            if (tag.HasSameClassAndValue(KrbApReqTag))
            {
                type = MessageType.KRB_AP_REQ;
                return true;
            }
            else if (tag.HasSameClassAndValue(KrbApRepTag))
            {
                type = MessageType.KRB_AS_REP;
                return true;
            }
            else
            {
                type = 0;
                return false;
            }
        }

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
            => CanDecode(encoded, out MessageType _);
    }
}
