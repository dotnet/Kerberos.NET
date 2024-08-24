// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities
{
    public class ClaimsSetMetadata : NdrPacObject
    {
        public override void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            var claimsSet = Compress(this.ClaimsSet, this.CompressionFormat, out int originalSize);

            buffer.WriteInt32LittleEndian(claimsSet.Length);

            buffer.WriteDeferredConformantArray(claimsSet);

            buffer.WriteInt32LittleEndian((int)this.CompressionFormat);
            buffer.WriteInt32LittleEndian(originalSize);

            buffer.WriteInt16LittleEndian(this.ReservedType);
            buffer.WriteInt32LittleEndian(this.ReservedFieldSize);

            // This.is the ReservedField that should be written to buffer as:
            // buffer.WriteDeferredConformantArray<byte>(this.ReservedField.Span)
            // However, it's currently reserved and should be 0
            buffer.WriteInt32LittleEndian(0);
        }

        private static ReadOnlySpan<byte> Compress(ClaimsSet claimsSet, CompressionFormat compressionFormat, out int originalSize)
        {
            using (var buffer = new NdrBuffer())
            {
                buffer.MarshalObject(claimsSet);

                ReadOnlySpan<byte> encoded = buffer.ToSpan(alignment: 8);

                originalSize = encoded.Length;

                if (compressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
                {
                    encoded = Compressions.Compress(encoded, compressionFormat);
                }

                return encoded;
            }
        }

        public override void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.ClaimSetSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredConformantArray<byte>(this.ClaimSetSize, v => this.ClaimsSet = this.UnmarshalClaimsSet(v));

            this.CompressionFormat = (CompressionFormat)buffer.ReadInt32LittleEndian();
            this.UncompressedClaimSetSize = buffer.ReadInt32LittleEndian();
            this.ReservedType = buffer.ReadInt16LittleEndian();
            this.ReservedFieldSize = buffer.ReadInt32LittleEndian();

            buffer.ReadDeferredConformantArray<byte>(this.ReservedFieldSize, v => this.ReservedField = v.ToArray());
        }

        private ClaimsSet UnmarshalClaimsSet(ReadOnlyMemory<byte> claimSet)
        {
            if (this.CompressionFormat != CompressionFormat.COMPRESSION_FORMAT_NONE)
            {
                claimSet = Compressions.Decompress(claimSet.Span, this.UncompressedClaimSetSize, this.CompressionFormat);
            }

            var claimsSet = new ClaimsSet();

            using (var buffer = new NdrBuffer(claimSet))
            {
                buffer.UnmarshalObject(claimsSet);
            }

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

        public ReadOnlyMemory<byte> ReservedField { get; set; }

        public override PacType PacType => PacType.CLIENT_CLAIMS;
    }
}
