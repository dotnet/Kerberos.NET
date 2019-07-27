using Kerberos.NET.Entities.Pac;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class ClaimsSetMetadata : NdrMessage, IPacElement
    {
        public override void WriteBody(NdrBinaryStream stream)
        {
            byte[] claimsSet = Compress(ClaimsSet, CompressionFormat, out int originalSize);

            stream.WriteDeferredBytes(claimsSet);

            stream.WriteUnsignedInt((int)CompressionFormat);
            stream.WriteUnsignedInt(originalSize);
            stream.WriteShort(ReservedType);

            stream.WriteDeferredBytes(ReservedField);
        }

        private static byte[] Compress(ClaimsSet claimsSet, CompressionFormat compressionFormat, out int originalSize)
        {
            var stream = new NdrBinaryStream();

            claimsSet.Encode(stream);

            var encoded = stream.ToMemory().ToArray();

            originalSize = encoded.Length;

            if (compressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                encoded = Compressions.Compress(encoded, compressionFormat);
            }

            return encoded;
        }

        public override void ReadBody(NdrBinaryStream Stream)
        {
            ClaimSetSize = Stream.ReadInt();

            Stream.Seek(4);

            CompressionFormat = (CompressionFormat)Stream.ReadInt();
            UncompressedClaimSetSize = Stream.ReadInt();
            ReservedType = Stream.ReadShort();
            ReservedFieldSize = Stream.ReadInt();

            Stream.Align(8);

            var size = Stream.ReadInt();

            if (size != ClaimSetSize)
            {
                throw new InvalidDataException($"Data length {size} doesn't match expected ClaimSetSize {ClaimSetSize}");
            }

            var claimSet = Stream.Read(ClaimSetSize);

            if (CompressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                claimSet = Compressions.Decompress(claimSet, UncompressedClaimSetSize, CompressionFormat);
            }

            ClaimsSet = new ClaimsSet();
            ClaimsSet.Decode(claimSet);

            ReservedField = Stream.Read(ReservedFieldSize);
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

        public PacType PacType { get; private set; } = PacType.CLIENT_CLAIMS;
    }
}