// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities
{
    [Flags]
    public enum PacAttributeFlags : int
    {
        None = 0,
        PacWasRequested = 1,
        PacWasGivenImplicitly = 2
    }

    public class PacAttributesInfo : PacObject
    {
        public int FlagsLength { get; set; } = 32;

        public PacAttributeFlags Flags { get; set; }

        public override PacType PacType => PacType.ATTRIBUTES_INFO;

        public override ReadOnlyMemory<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                buffer.WriteInt32LittleEndian(this.FlagsLength);
                buffer.WriteInt32LittleEndian((int)this.Flags);

                return buffer.ToMemory();
            }
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            using (var buffer = new NdrBuffer(bytes))
            {
                this.FlagsLength = buffer.ReadInt32LittleEndian();
                this.Flags = (PacAttributeFlags)buffer.ReadInt32LittleEndian();
            }
        }
    }
}
