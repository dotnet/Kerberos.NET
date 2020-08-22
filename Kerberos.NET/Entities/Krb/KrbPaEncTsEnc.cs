// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaEncTsEnc
    {
        internal static KrbPaEncTsEnc Now()
        {
            var ts = new KrbPaEncTsEnc();

            KerberosConstants.Now(out DateTimeOffset timestamp, out int usec);

            ts.PaTimestamp = timestamp;
            ts.PaUSec = usec;

            return ts;
        }
    }
}