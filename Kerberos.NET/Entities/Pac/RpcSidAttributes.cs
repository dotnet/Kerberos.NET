using Kerberos.NET.Ndr;
using System.Diagnostics;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Sid} {Attributes}")]
    public class RpcSidAttributes : INdrConformantStruct
    {
        public RpcSid Sid;
        public SidAttributes Attributes;

        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteConformantStruct(Sid);
            buffer.WriteInt32LittleEndian((int)Attributes);
        }

        public void MarshalConformance(NdrBuffer buffer)
        {
            //Sid.MarshalConformance(buffer);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            // expects 131124
            buffer.ReadConformantStruct<RpcSid>(p => Sid = p);

            Attributes = (SidAttributes)buffer.ReadInt32LittleEndian();
        }

        public void UnmarshalConformance(NdrBuffer buffer)
        {
            //new RpcSid().UnmarshalConformance(buffer);
        }
    }
}
