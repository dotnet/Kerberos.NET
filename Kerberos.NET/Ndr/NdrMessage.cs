// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public abstract class NdrPacObject : PacObject, INdrStruct // NDR thing
    {
        public abstract void Marshal(NdrBuffer buffer);

        public override ReadOnlyMemory<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                buffer.MarshalObject(this);

                return buffer.ToMemory(alignment: 8);
            }
        }

        public abstract void Unmarshal(NdrBuffer buffer);

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            using (var buffer = new NdrBuffer(bytes))
            {
                buffer.UnmarshalObject(this);
            }
        }
    }
}
