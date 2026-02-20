// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Represents gss_channel_bindings_struct per RFC 4121 section 4.1.1.2.
    /// </summary>
    public class GssChannelBindings
    {
        private const int SecChannelBindingsHeaderSize = 32;

        public int InitiatorAddrType { get; set; }

        public ReadOnlyMemory<byte> InitiatorAddress { get; set; }

        public int AcceptorAddrType { get; set; }

        public ReadOnlyMemory<byte> AcceptorAddress { get; set; }

        /// <summary>
        /// Protocol-specific channel binding data
        /// e.g. tls-server-end-point or tls-unique as per RFC 5929
        /// </summary>
        public ReadOnlyMemory<byte> ApplicationData { get; set; }

        /// <summary>
        /// Computes the 16-byte MD5 binding hash (Bnd field) per RFC 4121 section 4.1.1.2.
        /// </summary>
        public ReadOnlyMemory<byte> ComputeBindingHash()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            writer.Write(this.InitiatorAddrType);
            writer.Write(this.InitiatorAddress.Length);

            if (this.InitiatorAddress.Length > 0)
            {
                writer.Write(this.InitiatorAddress.ToArray());
            }

            writer.Write(this.AcceptorAddrType);
            writer.Write(this.AcceptorAddress.Length);

            if (this.AcceptorAddress.Length > 0)
            {
                writer.Write(this.AcceptorAddress.ToArray());
            }

            writer.Write(this.ApplicationData.Length);

            if (this.ApplicationData.Length > 0)
            {
                writer.Write(this.ApplicationData.ToArray());
            }

            var data = stream.ToArray();

            using var md5 = MD5.Create();
            return md5.ComputeHash(data);
        }

        /// <summary>
        /// Parses a raw SEC_CHANNEL_BINDINGS flat buffer (as returned by Windows SSPI) into a <see cref="GssChannelBindings"/>.
        /// </summary>
        [SupportedOSPlatform("windows")]
        public static GssChannelBindings FromSecChannelBindings(ReadOnlyMemory<byte> rawBuffer)
        {
            if (rawBuffer.Length < SecChannelBindingsHeaderSize)
            {
                throw new ArgumentException(
                    $"Buffer is too small to contain a SEC_CHANNEL_BINDINGS header. Expected at least {SecChannelBindingsHeaderSize} bytes.",
                    nameof(rawBuffer));
            }

            var span = rawBuffer.Span;

            var bindings = new GssChannelBindings
            {
                InitiatorAddrType = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0)),
            };

            int initiatorLength = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(4));
            int initiatorOffset = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(8));

            bindings.AcceptorAddrType = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(12));

            int acceptorLength = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(16));
            int acceptorOffset = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(20));

            int applicationDataLength = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(24));
            int applicationDataOffset = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(28));

            if (initiatorLength > 0)
            {
                bindings.InitiatorAddress = rawBuffer.Slice(initiatorOffset, initiatorLength);
            }

            if (acceptorLength > 0)
            {
                bindings.AcceptorAddress = rawBuffer.Slice(acceptorOffset, acceptorLength);
            }

            if (applicationDataLength > 0)
            {
                bindings.ApplicationData = rawBuffer.Slice(applicationDataOffset, applicationDataLength);
            }

            return bindings;
        }
    }
}
