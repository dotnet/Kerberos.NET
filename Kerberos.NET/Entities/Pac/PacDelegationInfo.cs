using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using System.Collections.Generic;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public class PacDelegationInfo : NdrPacObject, IPacElement
    {
        public override void Marshal(NdrBuffer buffer)
        {
            buffer.WriteStruct(S4U2ProxyTarget);

            buffer.WriteInt32LittleEndian(S4UTransitedServices.Count());

            buffer.WriteDeferredStructArray(S4UTransitedServices);
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            S4U2ProxyTarget = buffer.ReadStruct<RpcString>();

            var transitedListSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredStructArray<RpcString>(transitedListSize, v => S4UTransitedServices = v);
        }

        public RpcString S4U2ProxyTarget { get; set; }

        public IEnumerable<RpcString> S4UTransitedServices { get; set; }

        public PacType PacType => PacType.CONSTRAINED_DELEGATION_INFO;

        public override string ToString()
        {
            return $"{S4U2ProxyTarget} => {string.Join(", ", S4UTransitedServices)}";
        }
    }
}
