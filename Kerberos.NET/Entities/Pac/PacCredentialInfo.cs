using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using System;

namespace Kerberos.NET.Entities
{
    public class PacCredentialInfo : PacObject
    {
        public int Version { get; set; }

        public EncryptionType EncryptionType { get; set; }

        public ReadOnlyMemory<byte> SerializedData { get; set; }

        public override PacType PacType => PacType.CREDENTIAL_TYPE;

        public override ReadOnlySpan<byte> Marshal()
        {
            var buffer = new NdrBuffer();

            buffer.WriteInt32LittleEndian(Version);
            buffer.WriteInt32LittleEndian((int)EncryptionType);
            buffer.WriteSpan(SerializedData.Span);

            return buffer.ToSpan(alignment: 8);
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var stream = new NdrBuffer(bytes);

            Version = stream.ReadInt32LittleEndian();

            EncryptionType = (EncryptionType)stream.ReadInt32LittleEndian();

            SerializedData = stream.ReadMemory(stream.BytesAvailable);
        }
    }
}
