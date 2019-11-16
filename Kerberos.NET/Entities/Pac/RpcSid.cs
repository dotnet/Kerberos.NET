using Kerberos.NET.Ndr;
using System;
using System.Diagnostics;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcSid : INdrConformantStruct
    {
        public byte Revision;

        public byte SubAuthorityCount;

        public RpcSidIdentifierAuthority IdentifierAuthority;

        public ReadOnlyMemory<uint> SubAuthority;

        public void MarshalConformance(NdrBuffer buffer)
        {
            buffer.WriteInt32LittleEndian(SubAuthorityCount);
        }

        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteByte(Revision);
            buffer.WriteByte(SubAuthorityCount);
            buffer.WriteStruct(IdentifierAuthority);
            buffer.WriteFixedPrimitiveArray(SubAuthority.Span);
        }

        private int conformance;

        public void UnmarshalConformance(NdrBuffer buffer)
        {
            conformance = buffer.ReadInt32LittleEndian();
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            Revision = buffer.ReadByteLittleEndian();
            SubAuthorityCount = buffer.ReadByteLittleEndian();

            Debug.Assert(conformance == SubAuthorityCount);

            IdentifierAuthority = buffer.ReadStruct<RpcSidIdentifierAuthority>();
            SubAuthority = buffer.ReadFixedPrimitiveArray<uint>(SubAuthorityCount).AsMemory();
        }

        public SecurityIdentifier ToSecurityIdentifier()
        {
            return SecurityIdentifier.FromRpcSid(this);
        }

        public override string ToString()
        {
            return ToSecurityIdentifier().ToString();
        }
    }
}
