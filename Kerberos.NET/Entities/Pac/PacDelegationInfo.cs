using Kerberos.NET.Entities.Pac;
using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class PacDelegationInfo : NdrMessage, IPacElement
    {
        public override void WriteBody(NdrBinaryStream stream)
        {
            stream.WriteRPCUnicodeString(S4U2ProxyTarget);

            stream.WriteDeferredArray(S4UTransitedServices, true, (t, str) =>
            {
                str.WriteRPCUnicodeString(t.ToString());
            });
        }

        public override void ReadBody(NdrBinaryStream stream)
        {
            var s4uProxyTargetString = stream.ReadRPCUnicodeString();

            var transitListSize = stream.ReadInt();

            stream.ReadInt(); // transit pointer

            S4U2ProxyTarget = s4uProxyTargetString.ReadString(stream);

            var realCount = stream.ReadInt();

            if (realCount != transitListSize)
            {
                throw new InvalidDataException($"Expected S4UTransitedServices count {transitListSize} doesn't match actual count {realCount}");
            }

            var transitRpcStrings = new NdrString[realCount];

            for (var i = 0; i < realCount; i++)
            {
                transitRpcStrings[i] = stream.ReadRPCUnicodeString();
            }

            var transits = new List<string>();

            for (var i = 0; i < transitRpcStrings.Length; i++)
            {
                transits.Add(transitRpcStrings[i].ReadString(stream));
            }

            S4UTransitedServices = transits;
        }

        public string S4U2ProxyTarget { get; set; }

        public IEnumerable<string> S4UTransitedServices { get; set; }

        public PacType PacType => PacType.CONSTRAINED_DELEGATION_INFO;
    }
}