using Kerberos.NET.Ndr;
using System.Diagnostics;

#pragma warning disable S2344 // Enumeration type names should not have "Flags" or "Enum" suffixes

namespace Kerberos.NET.Entities.Pac
{
    [DebuggerDisplay("{Sid} {Attributes}")]
    public class RpcSidAttributes : INdrStruct
    {
        public RpcSid Sid;
        public SidAttributes Attributes;

        public void Marshal(NdrBuffer buffer)
        {
            buffer.WriteDeferredStruct(Sid);
            buffer.WriteInt32LittleEndian((int)Attributes);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            var self = this;

            buffer.ReadDeferredStruct<RpcSid>(p => self.Sid = p);

            Attributes = (SidAttributes)buffer.ReadInt32LittleEndian();
        }
    }
}
