// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public enum ClaimSourceType
    {
        CLAIMS_SOURCE_TYPE_AD = 1,
        CLAIMS_SOURCE_TYPE_CERTIFICATE
    }

    public class ClaimsArray : INdrStruct
    {
        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteInt32LittleEndian((int)this.ClaimSource);

            buffer.WriteInt32LittleEndian(this.Count);

            buffer.WriteDeferredStructArray(this.ClaimEntries);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.ClaimSource = (ClaimSourceType)buffer.ReadInt32LittleEndian();
            this.Count = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<ClaimEntry>(this.Count, v => this.ClaimEntries = v);
        }

        public ClaimSourceType ClaimSource { get; set; }

        [KerberosIgnore]
        public int Count { get; set; }

        public IEnumerable<ClaimEntry> ClaimEntries { get; set; }
    }
}