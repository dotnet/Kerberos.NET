// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{RelativeId} {Attributes}")]
    public class GroupMembership : INdrStruct
    {
        public uint RelativeId { get; set; }

        public SidAttributes Attributes { get; set; }

        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteUInt32LittleEndian(this.RelativeId);
            buffer.WriteInt32LittleEndian((int)this.Attributes);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.RelativeId = buffer.ReadUInt32LittleEndian();
            this.Attributes = (SidAttributes)buffer.ReadInt32LittleEndian();
        }
    }
}