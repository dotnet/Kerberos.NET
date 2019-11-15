using Kerberos.NET.Ndr;
using System;
using System.Text;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcSid : INdrStruct
    {
        public byte Revision;

        public byte SubAuthorityCount;

        public RpcSidIdentifierAuthority IdentifierAuthority;

        public ReadOnlyMemory<uint> SubAuthority;

        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteByte(Revision);
            buffer.WriteByte(SubAuthorityCount);
            buffer.WriteStruct(IdentifierAuthority);
            buffer.WriteFixedPrimitiveArray(SubAuthority.ToArray());
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            Revision = buffer.ReadByteLittleEndian();
            SubAuthorityCount = buffer.ReadByteLittleEndian();
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
