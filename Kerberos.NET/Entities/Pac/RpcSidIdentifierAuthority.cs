// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcSidIdentifierAuthority : INdrStruct
    {
        public ReadOnlyMemory<byte> IdentifierAuthority { get; set; } = new byte[6];

        public IdentifierAuthority Authority => (IdentifierAuthority)this.IdentifierAuthority.Slice(2, 4).AsLong();

        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteSpan(this.IdentifierAuthority.Span);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.IdentifierAuthority = buffer.ReadMemory(6);
        }
    }
}