// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{SName} @ {Realm}")]
    public partial class KrbTicket : IAsn1ApplicationEncoder<KrbTicket>
    {
        public KrbTicket DecodeAsApplication(ReadOnlyMemory<byte> data)
        {
            return Decode(ApplicationTag, data);
        }

        public KrbTicket()
        {
            this.TicketNumber = 5;
        }
    }
}