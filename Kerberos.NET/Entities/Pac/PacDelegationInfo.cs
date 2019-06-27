using Kerberos.NET.Entities.Pac;
using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class PacDelegationInfo : NdrMessage
    {
        public PacDelegationInfo(byte[] data)
            : base(data)
        {
            var s4uProxyTargetString = Stream.ReadRPCUnicodeString();

            var transitListSize = Stream.ReadInt();

            Stream.ReadInt(); // transit pointer

            S4U2ProxyTarget = s4uProxyTargetString.ReadString(Stream);

            var realCount = Stream.ReadInt();

            if (realCount != transitListSize)
            {
                throw new InvalidDataException($"Expected S4UTransitedServices count {transitListSize} doesn't match actual count {realCount}");
            }

            var transitRpcStrings = new PacString[realCount];

            for (var i = 0; i < realCount; i++)
            {
                transitRpcStrings[i] = Stream.ReadRPCUnicodeString();
            }

            var transits = new List<string>();

            for (var i = 0; i < transitRpcStrings.Length; i++)
            {
                transits.Add(transitRpcStrings[i].ReadString(Stream));
            }

            S4UTransitedServices = transits;
        }

        public string S4U2ProxyTarget { get; }

        public IEnumerable<string> S4UTransitedServices { get; }
    }
}