// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class NegotiationToken
    {
        private static readonly Asn1Tag NegotiateTag = new Asn1Tag(TagClass.Application, 0);

        public static bool CanDecode(ReadOnlyMemory<byte> encoded)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(NegotiateTag);
        }
    }
}