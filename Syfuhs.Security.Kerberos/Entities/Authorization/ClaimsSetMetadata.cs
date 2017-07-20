using Syfuhs.Security.Kerberos.Entities.Authorization;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class ClaimsSetMetadata
    {
        public ClaimsSetMetadata(byte[] data)
        {
            var pacStream = new PacBinaryReader(data);

            new RpcHeader(pacStream);

            ClaimSetSize = pacStream.ReadInt();
            var claimsSetPointer = pacStream.ReadInt();

            CompressionFormat = (CompressionFormat)pacStream.ReadInt();
            UncompressedClaimSetSize = pacStream.ReadInt();
            ReservedType = pacStream.ReadShort();
            ReservedFieldSize = pacStream.ReadInt();

            pacStream.Align(8);

            var claimSet = pacStream.Read(ClaimSetSize);

            ClaimsSet = new ClaimsSet(claimSet, CompressionFormat, UncompressedClaimSetSize);

            ReservedField = pacStream.Read(ReservedFieldSize);
        }

        public int ClaimSetSize { get; private set; }

        public ClaimsSet ClaimsSet { get; private set; }

        public CompressionFormat CompressionFormat { get; private set; }

        public int UncompressedClaimSetSize { get; private set; }

        public short ReservedType { get; private set; }

        public int ReservedFieldSize { get; private set; }

        public byte[] ReservedField { get; private set; }
    }

    public class ClaimsSet
    {
        public ClaimsSet(byte[] claims, CompressionFormat compression, int uncompressedLength)
        {
            if (compression != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                // IT GOES BOOM HERE

                claims = Compressions.Decompress(claims, uncompressedLength, compression);
            }

            // TODO... nothing below here works... yet.

            var pacStream = new PacBinaryReader(claims);

            new RpcHeader(pacStream);

            ArrayCount = pacStream.ReadInt();
            var arrayPointer = pacStream.ReadInt();

            ReservedType = pacStream.ReadShort();
            ReservedFieldSize = pacStream.ReadInt();

            pacStream.Align(8);

            ClaimsArray = ReadClaimsArray(pacStream, ArrayCount);

            ReservedField = pacStream.Read(ReservedFieldSize);
        }

        private IEnumerable<ClaimsArray> ReadClaimsArray(PacBinaryReader pacStream, int arrayCount)
        {
            var claims = new List<ClaimsArray>();

            for (var i = 0; i < ArrayCount; i++)
            {
                claims.Add(new ClaimsArray(pacStream));
            }

            return claims;
        }

        public int ArrayCount { get; private set; }

        public IEnumerable<ClaimsArray> ClaimsArray { get; private set; }

        public short ReservedType { get; private set; }

        public int ReservedFieldSize { get; private set; }

        public byte[] ReservedField { get; private set; }
    }

    public class ClaimsArray
    {
        public ClaimsArray(PacBinaryReader pacStream)
        {
            ;

            ClaimSource = (ClaimSourceType)pacStream.ReadInt();
            ClaimsCount = pacStream.ReadUnsignedInt();

            var claims = new List<ClaimEntry>();

            for (var i = 0; i < ClaimsCount; i++)
            {
                claims.Add(new ClaimEntry(pacStream));
            }

            ClaimEntries = claims;
        }

        public ClaimSourceType ClaimSource { get; private set; }

        public uint ClaimsCount { get; private set; }

        public IEnumerable<ClaimEntry> ClaimEntries { get; private set; }
    }

    public enum ClaimSourceType
    {
        CLAIMS_SOURCE_TYPE_AD = 1,
        CLAIMS_SOURCE_TYPE_CERTIFICATE
    }

    public enum ClaimType
    {
        CLAIM_TYPE_INT64 = 1,
        CLAIM_TYPE_UINT64 = 2,
        CLAIM_TYPE_STRING = 3,
        CLAIM_TYPE_BOOLEAN = 6
    }

    public class ClaimEntry
    {
        public ClaimEntry(PacBinaryReader pacStream)
        {

        }

        public string Id { get; private set; }

        public ClaimType Type { get; private set; }

        public uint ValueCount { get; private set; }

        public long[] Int64Values { get; private set; }

        public ulong[] UInt64Values { get; private set; }

        public string[] StringValues { get; private set; }

        public ulong BooleanValues { get; private set; }
    }
}