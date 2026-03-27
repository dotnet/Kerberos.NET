// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities
{
    public class PacRequestor : PacObject
    {
        public SecurityIdentifier RequestorSid { get; set; }

        public override PacType PacType => PacType.REQUESTOR;

        public override ReadOnlyMemory<byte> Marshal()
        {
            using (var buffer = new NdrBuffer())
            {
                var rpcSid = this.RequestorSid.ToRpcSid();

                buffer.WriteByte(rpcSid.Revision);
                buffer.WriteByte(rpcSid.SubAuthorityCount);
                buffer.WriteSpan(rpcSid.IdentifierAuthority.IdentifierAuthority.Span);
                buffer.WriteFixedPrimitiveArray(rpcSid.SubAuthority.Span);

                return buffer.ToMemory();
            }
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            using (var buffer = new NdrBuffer(bytes))
            {
                var revision = buffer.ReadByteLittleEndian();
                var subAuthorityCount = buffer.ReadByteLittleEndian();

                var identifierAuthority = new RpcSidIdentifierAuthority();
                identifierAuthority.Unmarshal(buffer);

                var subAuthorities = buffer.ReadFixedPrimitiveArray<uint>(subAuthorityCount).ToArray();

                var rpcSid = new RpcSid
                {
                    Revision = revision,
                    SubAuthorityCount = subAuthorityCount,
                    IdentifierAuthority = identifierAuthority,
                    SubAuthority = subAuthorities
                };

                this.RequestorSid = rpcSid.ToSecurityIdentifier();
            }
        }
    }
}
