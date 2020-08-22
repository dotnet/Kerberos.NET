// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class NegotiateMessageHeader
    {
        public ulong Signature { get; set; }

        public NegotiateMessageType MessageType { get; }

        public uint SequenceNumber { get; }

        [KerberosIgnore]
        public uint CbHeaderLength { get; }

        [KerberosIgnore]
        public uint CbMessageLength { get; }

        public Guid ConversationId { get; }

        private const ulong HeaderSignature = 0x535458454f47454e;

        public static bool HasHeader(ReadOnlyMemory<byte> data)
        {
            return HasHeader(data, out _, out _);
        }

        private static bool HasHeader(ReadOnlyMemory<byte> data, out BinaryReader reader, out ulong actualSignature)
        {
            reader = new BinaryReader(new MemoryStream(data.ToArray()));

            actualSignature = reader.ReadUInt64();

            return actualSignature == HeaderSignature;
        }

        public NegotiateMessageHeader(ReadOnlyMemory<byte> data, out BinaryReader reader)
        {
            if (!HasHeader(data, out reader, out ulong signature))
            {
                throw new InvalidDataException($"Unknown Negotiate Extension Signature. Actual: 0x{signature:X}; Expected: 0x{HeaderSignature:X}");
            }

            this.Signature = signature;
            this.MessageType = (NegotiateMessageType)reader.ReadInt32();
            this.SequenceNumber = reader.ReadUInt32();
            this.CbHeaderLength = reader.ReadUInt32();
            this.CbMessageLength = reader.ReadUInt32();

            this.ConversationId = new Guid(reader.ReadBytes(16));
        }
    }
}