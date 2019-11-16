using Kerberos.NET.Ndr;
using System.Diagnostics;

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

        public void MarshalConformance(NdrBuffer buffer) { }

        public void Unmarshal(NdrBuffer buffer)
        {
            buffer.ReadConformantStruct<RpcSid>(p => Sid = p);

            Attributes = (SidAttributes)buffer.ReadInt32LittleEndian();
        }

        public void UnmarshalConformance(NdrBuffer buffer) { }
    }
}
