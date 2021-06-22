// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using static Kerberos.NET.Entities.KerberosConstants;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaEncTsEnc
    {
        internal static KrbPaEncTsEnc CreateForNow()
        {
            var ts = new KrbPaEncTsEnc();

            Now(out DateTimeOffset timestamp, out int usec);

            ts.PaTimestamp = timestamp;
            ts.PaUSec = usec;

            return ts;
        }
    }
}
