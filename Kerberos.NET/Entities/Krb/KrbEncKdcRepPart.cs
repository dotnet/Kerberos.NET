// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncKdcRepPart
    {
        public virtual KeyUsage KeyUsage => 0;

        private protected static bool CanDecode(ReadOnlyMemory<byte> encoded, Asn1Tag expectedTag)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out _, out _);

            return tag.HasSameClassAndValue(expectedTag);
        }
    }
}
