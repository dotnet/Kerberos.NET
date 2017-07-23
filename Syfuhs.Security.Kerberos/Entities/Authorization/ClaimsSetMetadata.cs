using Syfuhs.Security.Kerberos.Entities.Authorization;
using System.Collections.Generic;
using System;

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
            var size = pacStream.ReadInt();

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
                claims = Compressions.Decompress(claims, uncompressedLength, compression);
            }

            var pacStream = new PacBinaryReader(claims);

            new RpcHeader(pacStream);

            ArrayCount = pacStream.ReadInt();
            var arrayPointer = pacStream.ReadInt();

            ReservedType = pacStream.ReadShort();
            ReservedFieldSize = pacStream.ReadInt();

            ReservedField = pacStream.Read(ReservedFieldSize);

            pacStream.Align(8);

            ClaimsArray = ReadClaimsArray(pacStream, ArrayCount);
        }

        private IEnumerable<ClaimsArray> ReadClaimsArray(PacBinaryReader pacStream, int arrayCount)
        {
            //var bytes = pacStream.ReadToEnd();

            var count = pacStream.ReadInt();

            var claims = new List<ClaimsArray>();

            for (var i = 0; i < arrayCount; i++)
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

            foreach (var entry in claims)
            {
                entry.ReadValue(pacStream);
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
            Id = pacStream.ReadString();

            //var bytes = pacStream.ReadToEnd();
            ;

            pacStream.Align(4);

            ValueCount = pacStream.ReadUnsignedInt();

            var sdf = pacStream.ReadInt();

            var values = new object[ValueCount];

            Type = ClaimType.CLAIM_TYPE_STRING;

            for (var i = 0; i < ValueCount; i++)
            {
                switch (Type)
                {
                    case ClaimType.CLAIM_TYPE_BOOLEAN:
                        values[i] = Convert.ToBoolean(pacStream.ReadInt());
                        break;
                    case ClaimType.CLAIM_TYPE_INT64:
                        values[i] = pacStream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_UINT64:
                        values[i] = (ulong)pacStream.ReadLong();
                        break;
                    case ClaimType.CLAIM_TYPE_STRING:
                        values[i] = pacStream.ReadString();
                        break;
                }

                //values[i] = pacStream.ReadString();
            }
        }

        public string Id { get; private set; }

        public ClaimType Type { get; private set; }

        public uint ValueCount { get; private set; }

        public long[] Int64Values { get; private set; }

        public ulong[] UInt64Values { get; private set; }

        public string[] StringValues { get; private set; }

        public ulong BooleanValues { get; private set; }

        internal void ReadValue(PacBinaryReader pacStream)
        {
            Id = pacStream.ReadString();

            ValueCount = pacStream.ReadUnsignedInt();

            var valueStrs = new PacString[ValueCount];

            for (var i = 0; i < ValueCount; i++)
            {
                valueStrs[i] = pacStream.ReadRPCUnicodeString();
            }

            var valueStrings = new string[ValueCount];

            for (var i = 0; i < ValueCount; i++)
            {
                valueStrings[i] = valueStrs[i].ReadString(pacStream);
            }
        }
    }
}