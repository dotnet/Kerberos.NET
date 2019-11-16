using Kerberos.NET.Ndr;
using System;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcSidIdentifierAuthority : INdrStruct
    {
        public ReadOnlyMemory<byte> IdentifierAuthority = new byte[6];

        public IdentifierAuthority Authority => (IdentifierAuthority)IdentifierAuthority.Slice(2, 4).AsLong();

        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteSpan(IdentifierAuthority.Span);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            IdentifierAuthority = buffer.ReadMemory(6);
        }
    }
}
