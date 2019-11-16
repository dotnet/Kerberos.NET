using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using System;

namespace Kerberos.NET.Entities
{
    public class ClaimsSetMetadata : NdrPacObject
    {
        public override void Marshal(NdrBuffer buffer)
        {
            var claimsSet = Compress(ClaimsSet, CompressionFormat, out int originalSize);

            buffer.WriteInt32LittleEndian(claimsSet.Length);

            buffer.WriteDeferredConformantArray(claimsSet);

            buffer.WriteInt32LittleEndian((int)CompressionFormat);
            buffer.WriteInt32LittleEndian(originalSize);

            buffer.WriteInt16LittleEndian(ReservedType);
            buffer.WriteInt32LittleEndian(ReservedFieldSize);

            buffer.WriteDeferredConformantArray<byte>(ReservedField);
        }

        private static ReadOnlySpan<byte> Compress(ClaimsSet claimsSet, CompressionFormat compressionFormat, out int originalSize)
        {
            var buffer = new NdrBuffer();

            buffer.MarshalObject(claimsSet);

            ReadOnlySpan<byte> encoded = buffer.ToSpan();

            originalSize = encoded.Length;

            if (compressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                encoded = Compressions.Compress(encoded, compressionFormat);
            }

            return encoded;
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            ClaimSetSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredConformantArray<byte>(ClaimSetSize, v => ClaimsSet = UnmarshalClaimsSet(v));

            CompressionFormat = (CompressionFormat)buffer.ReadInt32LittleEndian();
            UncompressedClaimSetSize = buffer.ReadInt32LittleEndian();
            ReservedType = buffer.ReadInt16LittleEndian();
            ReservedFieldSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredConformantArray<byte>(ReservedFieldSize, v => ReservedField = v.ToArray());
        }

        private ClaimsSet UnmarshalClaimsSet(ReadOnlyMemory<byte> claimSet)
        {
            if (CompressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                claimSet = Compressions.Decompress(claimSet.Span, UncompressedClaimSetSize, CompressionFormat);
            }

            var claimsSet = new ClaimsSet();
            new NdrBuffer(claimSet).UnmarshalObject(claimsSet);

            return claimsSet;
        }

        [KerberosIgnore]
        public int ClaimSetSize { get; set; }

        public ClaimsSet ClaimsSet { get; set; }

        public CompressionFormat CompressionFormat { get; set; }

        [KerberosIgnore]
        public int UncompressedClaimSetSize { get; set; }

        public short ReservedType { get; set; }

        [KerberosIgnore]
        public int ReservedFieldSize { get; set; }

        public byte[] ReservedField { get; set; }

        public override PacType PacType => PacType.CLIENT_CLAIMS;
    }
}
