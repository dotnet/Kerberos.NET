using Kerberos.NET.Ndr;
using System;
using System.Diagnostics;
using System.Text;

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
            buffer.WriteFixedPrimitiveArray(SubAuthority.ToArray());
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

        private string sddl;

        public override string ToString()
        {
            if (sddl == null)
            {
                var result = new StringBuilder();

                result.AppendFormat("S-1-{0}", (long)IdentifierAuthority.Authority);

                for (int i = 0; i < SubAuthority.Length; i++)
                {
                    result.AppendFormat("-{0}", SubAuthority.Span[i]);
                }

                sddl = result.ToString().ToUpperInvariant();
            }

            return sddl;
        }
    }
}
