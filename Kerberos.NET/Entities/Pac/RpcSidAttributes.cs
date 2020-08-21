// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Sid} {Attributes}")]
    public class RpcSidAttributes : INdrConformantStruct
    {
        public RpcSid Sid { get; set; }

        public SidAttributes Attributes { get; set; }

        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteConformantStruct(this.Sid);
            buffer.WriteInt32LittleEndian((int)this.Attributes);
        }

        public void MarshalConformance(NdrBuffer buffer)
        {
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.ReadConformantStruct<RpcSid>(p => this.Sid = p);

            this.Attributes = (SidAttributes)buffer.ReadInt32LittleEndian();
        }

        public void UnmarshalConformance(NdrBuffer buffer)
        {
        }
    }
}