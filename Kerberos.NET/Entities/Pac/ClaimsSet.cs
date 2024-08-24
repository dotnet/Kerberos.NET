// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public class ClaimsSet : INdrStruct
    {
        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteInt32LittleEndian(this.ClaimsArray.Count());
            buffer.WriteDeferredStructArray(this.ClaimsArray);

            buffer.WriteInt16LittleEndian(this.ReservedType);
            buffer.WriteInt32LittleEndian(this.ReservedFieldSize);

            // This.is the ReservedField that should be written to buffer as:
            // WriteDeferredConformantArray<byte>(this.ReservedField.Span)
            // However, it's currently reserved and should be 0
            buffer.WriteInt32LittleEndian(0);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.Count = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<ClaimsArray>(this.Count, v => this.ClaimsArray = v);

            this.ReservedType = buffer.ReadInt16LittleEndian();
            this.ReservedFieldSize = buffer.ReadInt32LittleEndian();
            buffer.ReadDeferredConformantArray<byte>(this.ReservedFieldSize, v => this.ReservedField = v.ToArray());
        }

        [KerberosIgnore]
        public int Count { get; set; }

        public IEnumerable<ClaimsArray> ClaimsArray { get; set; }

        public short ReservedType { get; set; }

        [KerberosIgnore]
        public int ReservedFieldSize { get; set; }

        public ReadOnlyMemory<byte> ReservedField { get; set; }
    }
}
