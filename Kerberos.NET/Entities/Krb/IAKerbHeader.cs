// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    public partial class IAKerbHeader
    {
        public static IAKerbHeader DecodePartial(ref Memory<byte> message)
        {
            var reader = new AsnReader(message, AsnEncodingRules.DER);

            Decode(reader, out IAKerbHeader header);

            if (reader.RemainingBytes > 0)
            {
                message = message.Slice(message.Length - reader.RemainingBytes);
            }
            else
            {
                message = Memory<byte>.Empty;
            }

            return header;
        }
    }
}
