using System;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class NegotiateExtension
    {
        public NegotiateExtension(ReadOnlyMemory<byte> data)
        {
            Message = new NegotiateMessage(data);
        }

        public NegotiateMessage Message { get; }

        internal static bool CanDecode(ReadOnlyMemory<byte> data)
        {
            return NegotiateMessageHeader.HasHeader(data);
        }
    }

    public class NegotiateMessage
    {
        public NegotiateMessageHeader Header { get; }

        public byte[] Random { get; }

        public ulong ProtocolVersion { get; }

        public AuthScheme AuthSchemes { get; }

        public ExtensionVector Extensions { get; }

        public NegotiateMessage(ReadOnlyMemory<byte> data)
        {
            Header = new NegotiateMessageHeader(data, out BinaryReader reader);

            Random = reader.ReadBytes(32);
            ProtocolVersion = reader.ReadUInt64();

            AuthSchemes = new AuthScheme(reader);
            Extensions = new ExtensionVector(reader);

            reader.Dispose();
        }
    }

    public class AuthScheme
    {
        [KerberosIgnore]
        public uint AuthSchemeArrayOffset { get; }

        [KerberosIgnore]
        public ushort AuthSchemeCount { get; }

        public Guid[] Schemes { get; }

        public AuthScheme(BinaryReader reader)
        {
            AuthSchemeArrayOffset = reader.ReadUInt32();
            AuthSchemeCount = reader.ReadUInt16();

            Schemes = new Guid[AuthSchemeCount];

            var offset = reader.BaseStream.Position;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            reader.BaseStream.Seek(AuthSchemeArrayOffset, SeekOrigin.Begin);

            for (var i = 0; i < AuthSchemeCount; i++)
            {
                var scheme = reader.ReadBytes(16);

                Schemes[i] = new Guid(scheme);
            }

            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
        }
    }

    public class Extension
    {
        public uint Type { get; }

        public byte[] Value { get; }

        public Extension(BinaryReader reader)
        {
            Type = reader.ReadUInt32();

            var offset = reader.ReadUInt32();
            var length = reader.ReadUInt32();

            var current = reader.BaseStream.Position;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            reader.BaseStream.Seek(offset, SeekOrigin.Begin);

            Value = reader.ReadBytes((int)length);

            reader.BaseStream.Seek(current, SeekOrigin.Begin);
        }
    }

    public class ExtensionVector
    {
        [KerberosIgnore]
        public uint ExtensionArrayOffset { get; }

        [KerberosIgnore]
        public ushort ExtensionCount { get; }

        public Extension[] Extensions { get; }

        public ExtensionVector(BinaryReader reader)
        {
            ExtensionArrayOffset = reader.ReadUInt32();
            ExtensionCount = reader.ReadUInt16();

            Extensions = new Extension[ExtensionCount];

            var offset = reader.BaseStream.Position;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            reader.BaseStream.Seek(ExtensionArrayOffset, SeekOrigin.Begin);

            for (var i = 0; i < ExtensionCount; i++)
            {
                Extensions[i] = new Extension(reader);
            }

            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
        }
    }

    public class NegotiateMessageHeader
    {
        public ulong Signature;

        public NegotiateMessageType MessageType { get; }

        public uint SequenceNumber { get; }

        [KerberosIgnore]
        public uint cbHeaderLength { get; }

        [KerberosIgnore]
        public uint cbMessageLength { get; }

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
            if (!HasHeader(data, out reader, out Signature))
            {
                throw new InvalidDataException($"Unknown Negotiate Extension Signature. Actual: 0x{Signature:X}; Expected: 0x{HeaderSignature:X}");
            }

            MessageType = (NegotiateMessageType)reader.ReadInt32();
            SequenceNumber = reader.ReadUInt32();
            cbHeaderLength = reader.ReadUInt32();
            cbMessageLength = reader.ReadUInt32();

            ConversationId = new Guid(reader.ReadBytes(16));
        }
    }

    public enum NegotiateMessageType
    {
        MESSAGE_TYPE_INITIATOR_NEGO = 0,
        MESSAGE_TYPE_ACCEPTOR_NEGO,
        MESSAGE_TYPE_INITIATOR_META_DATA,
        MESSAGE_TYPE_ACCEPTOR_META_DATA,
        MESSAGE_TYPE_CHALLENGE,
        MESSAGE_TYPE_AP_REQUEST,
        MESSAGE_TYPE_VERIFY,
        MESSAGE_TYPE_ALERT,
    }
}
