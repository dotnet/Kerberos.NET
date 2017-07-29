using System.Collections.Generic;
using System.IO;

namespace Syfuhs.Security.Kerberos.Entities.Authorization
{
    public class ClaimsSet : NdrMessage
    {
        public ClaimsSet(byte[] claims)
        {
            var pacStream = new NdrBinaryReader(claims);

            Header = new RpcHeader(pacStream);

            Count = pacStream.ReadInt();

            pacStream.Seek(4);

            ReservedType = pacStream.ReadShort();
            ReservedFieldSize = pacStream.ReadInt();

            ReservedField = pacStream.Read(ReservedFieldSize);

            pacStream.Align(8);

            ClaimsArray = ReadClaimsArray(pacStream);
        }

        private IEnumerable<ClaimsArray> ReadClaimsArray(NdrBinaryReader pacStream)
        {
            var count = pacStream.ReadInt();

            if (count != Count)
            {
                throw new InvalidDataException($"Array count {Count} doesn't match actual count {count}");
            }

            var claims = new List<ClaimsArray>();

            for (var i = 0; i < Count; i++)
            {
                claims.Add(new ClaimsArray(pacStream));
            }

            return claims;
        }

        public int Count { get; private set; }

        public IEnumerable<ClaimsArray> ClaimsArray { get; private set; }

        public short ReservedType { get; private set; }

        public int ReservedFieldSize { get; private set; }

        public byte[] ReservedField { get; private set; }
    }
}
