using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities.Pac
{
    public class ClaimsSet : NdrMessage
    {
        public ClaimsSet(byte[] claims)
            : base(claims)
        {
            Count = Stream.ReadInt();

            Stream.Seek(4);

            ReservedType = Stream.ReadShort();
            ReservedFieldSize = Stream.ReadInt();

            ReservedField = Stream.Read(ReservedFieldSize);

            Stream.Align(8);

            ClaimsArray = ReadClaimsArray(Stream);
        }

        private IEnumerable<ClaimsArray> ReadClaimsArray(NdrBinaryReader stream)
        {
            var count = stream.ReadInt();

            if (count != Count)
            {
                throw new InvalidDataException($"Array count {Count} doesn't match actual count {count}");
            }

            var claims = new List<ClaimsArray>();

            for (var i = 0; i < Count; i++)
            {
                claims.Add(new ClaimsArray(stream));
            }

            return claims;
        }

        [KerberosIgnore]
        public int Count { get; }

        public IEnumerable<ClaimsArray> ClaimsArray { get; }

        public short ReservedType { get; }

        [KerberosIgnore]
        public int ReservedFieldSize { get; }

        public byte[] ReservedField { get; }
    }
}
