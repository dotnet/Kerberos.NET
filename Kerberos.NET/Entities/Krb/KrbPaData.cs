// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Kerberos.NET.Entities
{
    [DebuggerDisplay("{Type} {Value.Length}")]
    public partial class KrbPaData
    {
        public IEnumerable<KrbETypeInfo2Entry> DecodeETypeInfo2()
        {
            if (this.Type != PaDataType.PA_ETYPE_INFO2)
            {
                throw new InvalidOperationException($"Cannot parse EType Info because type is {this.Type}");
            }

            var info = KrbETypeInfo2.Decode(this.Value);

            return info.ETypeInfo;
        }

        public KrbApReq DecodeApReq()
        {
            if (this.Type != PaDataType.PA_TGS_REQ)
            {
                throw new InvalidOperationException($"Cannot parse the TGS ApReq because type is {this.Type}");
            }

            return new KrbApReq().DecodeAsApplication(this.Value);
        }
    }
}