using System;
using System.IO;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class NegotiateExtension
    {
        public NegotiateExtension(byte[] data)
        {
            Message = new NegotiateMessage(new BinaryReader(new MemoryStream(data)));
        }

        public NegotiateMessage Message { get; private set; }
    }

    public class NegotiateMessage
    {
        public NegotiateMessageHeader Header { get; private set; }

        public byte[] Random { get; private set; }

        public ulong ProtocolVersion { get; private set; }

        public AuthScheme AuthSchemes { get; private set; }

        public ExtensionVector Extensions { get; private set; }

        public NegotiateMessage(BinaryReader reader)
        {
            Header = new NegotiateMessageHeader(reader);

            Random = reader.ReadBytes(32);
            ProtocolVersion = reader.ReadUInt64();

            AuthSchemes = new AuthScheme(reader);
            Extensions = new ExtensionVector(reader);
        }
    }


    public class AuthScheme
    {
        public uint AuthSchemeArrayOffset { get; private set; }

        public ushort AuthSchemeCount { get; private set; }

        public Guid[] Schemes { get; private set; }

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
                Schemes[i] = new Guid(reader.ReadBytes(16));
            }

            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
        }
    }

    public class Extension
    {
        public uint Type { get; private set; }

        public byte[] Value { get; private set; }

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
        public uint ExtensionArrayOffset { get; private set; }

        public ushort ExtensionCount { get; private set; }

        public Extension[] Extensions { get; private set; }

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
        public ulong Signature { get; private set; }

        public NegotiateMessageType MessageType { get; private set; }

        public uint SequenceNumber { get; private set; }

        public uint cbHeaderLength { get; private set; }

        public uint cbMessageLength { get; private set; }

        public Guid ConversationId { get; private set; }

        private const ulong HeaderSignature = 0x535458454f47454e;

        public NegotiateMessageHeader(BinaryReader reader)
        {
            Signature = reader.ReadUInt64();

            if (Signature != HeaderSignature)
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
