// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcSid : INdrConformantStruct
    {
        public byte Revision { get; set; }

        public byte SubAuthorityCount { get; set; }

        public RpcSidIdentifierAuthority IdentifierAuthority { get; set; }

        public ReadOnlyMemory<uint> SubAuthority { get; set; }

        public void MarshalConformance(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteInt32LittleEndian(this.SubAuthorityCount);
        }

        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteByte(this.Revision);
            buffer.WriteByte(this.SubAuthorityCount);
            buffer.WriteStruct(this.IdentifierAuthority);
            buffer.WriteFixedPrimitiveArray(this.SubAuthority.Span);
        }

        private int conformance;

        public void UnmarshalConformance(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.conformance = buffer.ReadInt32LittleEndian();
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.Revision = buffer.ReadByteLittleEndian();
            this.SubAuthorityCount = buffer.ReadByteLittleEndian();

            Debug.Assert(this.conformance == this.SubAuthorityCount);

            this.IdentifierAuthority = buffer.ReadStruct<RpcSidIdentifierAuthority>();
            this.SubAuthority = buffer.ReadFixedPrimitiveArray<uint>(this.SubAuthorityCount).ToArray();
        }

        public SecurityIdentifier ToSecurityIdentifier()
        {
            return SecurityIdentifier.FromRpcSid(this);
        }

        public override string ToString()
        {
            return this.ToSecurityIdentifier().ToString();
        }
    }
}
