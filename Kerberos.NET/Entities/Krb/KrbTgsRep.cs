// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsRep : IAsn1ApplicationEncoder<KrbTgsRep>
    {
        public KrbTgsRep()
        {
            this.MessageType = MessageType.KRB_TGS_REP;
        }

        public KrbTgsRep DecodeAsApplication(ReadOnlyMemory<byte> encoded)
        {
            return DecodeApplication(encoded);
        }
    }
}