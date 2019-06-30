using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class NtlmMessage
    {
        internal static readonly byte[] MessageSignature = Encoding.ASCII.GetBytes("NTLMSSP\0");

        public static bool CanReadNtlmMessage(byte[] ntlm)
        {
            return CanReadNtlmMessage(ntlm, out _, out _);
        }

        public static bool CanReadNtlmMessage(byte[] ntlm, out byte[] actualSignature, out BinaryReader reader)
        {
            reader = new BinaryReader(new MemoryStream(ntlm));

            actualSignature = reader.ReadBytes(MessageSignature.Length);

            return actualSignature.SequenceEqual(MessageSignature);
        }

        public NtlmMessage(byte[] ntlm)
        {
            if (!CanReadNtlmMessage(ntlm, out byte[] actualSignature, out BinaryReader reader))
            {
                throw new InvalidDataException($"Unknown NTLM message signature. Actual: 0x{actualSignature:X}; Expected: 0x{MessageSignature:X}");
            }

            MessageType = (NtlmMessageType)reader.ReadInt32();
            Flags = (NtlmNegotiateFlag)reader.ReadInt32();

            var domainNameLength = reader.ReadInt16();
            var domainNameMaxLength = reader.ReadInt16();
            var domainNameBufferOffset = reader.ReadInt32();

            var workstationLength = reader.ReadInt16();
            var workstationMaxLength = reader.ReadInt16();
            var workstationBufferOffset = reader.ReadInt32();

            var version = reader.ReadInt64();

            if ((Flags & NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) > 0)
            {
                reader.BaseStream.Seek(domainNameBufferOffset, SeekOrigin.Begin);

                DomainName = Encoding.ASCII.GetString(reader.ReadBytes(domainNameLength));
            }

            if ((Flags & NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) > 0)
            {
                reader.BaseStream.Seek(workstationBufferOffset, SeekOrigin.Begin);

                Workstation = Encoding.ASCII.GetString(reader.ReadBytes(workstationLength));
            }

            reader.Dispose();
        }

        public NtlmMessageType MessageType { get; }

        public NtlmNegotiateFlag Flags { get; }

        public string DomainName { get; }

        public string Workstation { get; }
    }

    public enum NtlmMessageType : uint
    {
        Negotiate = 1,
        Challenge = 2,
        Authenticate = 3
    }

    [Flags]
    public enum NtlmNegotiateFlag
    {
        NTLMSSP_NEGOTIATE_56 = 1 << 31,
        NTLMSSP_NEGOTIATE_KEY_EXCH = 1 << 30,
        NTLMSSP_NEGOTIATE_128 = 1 << 29,
        r1 = 1 << 28,
        r2 = 1 << 27,
        r3 = 1 << 26,
        NTLMSSP_NEGOTIATE_VERSION = 1 << 25,
        r4 = 1 << 24,
        NTLMSSP_NEGOTIATE_TARGET_INFO = 1 << 23,
        NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 1 << 22,
        r5 = 1 << 21,
        NTLMSSP_NEGOTIATE_IDENTIFY = 1 << 20,
        NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 1 << 19,
        r6 = 1 << 18,
        NTLMSSP_TARGET_TYPE_SERVER = 1 << 17,
        NTLMSSP_TARGET_TYPE_DOMAIN = 1 << 16,
        NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 1 << 15,
        r7 = 1 << 14,
        NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 1 << 13,
        NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = 1 << 12,
        NTLMSSP_NEGOTIATE_ANONYMOUS_CONNECTION = 1 << 11,
        r8 = 1 << 10,
        NTLMSSP_NEGOTIATE_NTLM_V1 = 1 << 9,
        r9 = 1 << 8,
        NTLMSSP_NEGOTIATE_LM_KEY = 1 << 7,
        NTLMSSP_NEGOTIATE_DATAGRAM = 1 << 6,
        NTLMSSP_NEGOTIATE_SEAL = 1 << 5,
        NTLMSSP_NEGOTIATE_SIGN = 1 << 4,
        r10 = 1 << 3,
        NTLMSSP_REQUEST_TARGET = 1 << 2,
        NTLM_NEGOTIATE_OEM = 1 << 1,
        NTLMSSP_NEGOTIATE_UNICODE = 1 << 0
    }
}
