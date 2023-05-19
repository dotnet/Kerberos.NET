// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Asn1;
using System.Text;

namespace Kerberos.NET.Entities
{
    public class NtlmMessage
    {
        private static readonly Asn1Tag GssApplicationTag = new(TagClass.Application, 0);
        private static readonly Asn1Tag NtlmContextTag = new(TagClass.ContextSpecific, 1);

        internal static readonly byte[] MessageSignature = Encoding.ASCII.GetBytes("NTLMSSP\0");

        public static bool CanReadNtlmMessage(ReadOnlyMemory<byte> ntlm)
        {
            return CanReadNtlmMessage(ntlm, out _, out _);
        }

        public static bool CanReadNtlmMessage(ReadOnlyMemory<byte> ntlm, out byte[] actualSignature, out BinaryReader reader)
        {
            return CanReadNtlmMessage(ntlm, out actualSignature, out reader, out _);
        }

        private static bool CanReadNtlmMessage(ReadOnlyMemory<byte> ntlm, out byte[] actualSignature, out BinaryReader reader, out AsnReader asnReader)
        {
            asnReader = null;

            reader = new BinaryReader(new MemoryStream(ntlm.ToArray()));

            actualSignature = reader.ReadBytes(MessageSignature.Length);

            if (actualSignature.SequenceEqual(MessageSignature))
            {
                return true;
            }

            asnReader = new AsnReader(ntlm, AsnEncodingRules.DER);

            var peekTag = asnReader.PeekTag();

            if (AsnReader.IsExpectedTag(peekTag, GssApplicationTag, UniversalTagNumber.Sequence))
            {
                return false;
            }

            return AsnReader.IsExpectedTag(peekTag, NtlmContextTag, UniversalTagNumber.Sequence);
        }

        public NtlmMessage(ReadOnlyMemory<byte> ntlm)
        {
            bool canRead;
            BinaryReader reader = null;

            try
            {
                do
                {
                    canRead = CanReadNtlmMessage(ntlm, out byte[] actualSignature, out reader, out AsnReader asnReader);

                    if (!canRead)
                    {
                        throw new InvalidDataException($"Unknown NTLM message signature. Actual: 0x{actualSignature:X}; Expected: 0x{MessageSignature:X}");
                    }

                    if (asnReader == null)
                    {
                        break;
                    }

                    asnReader = asnReader.ReadSequence(NtlmContextTag);
                    NegTokenResp.Decode(asnReader, out NegTokenResp resp);

                    ntlm = resp.ResponseToken.Value;
                }
                while (canRead);

                this.MessageType = (NtlmMessageType)reader.ReadInt32();

                if (this.MessageType != NtlmMessageType.Challenge)
                {
                    return;
                }

                this.Flags = (NtlmNegotiateFlag)reader.ReadInt32();

                var domainNameLength = reader.ReadInt16();
                _ = reader.ReadInt16(); // domain name max length
                var domainNameBufferOffset = reader.ReadInt32();

                var workstationLength = reader.ReadInt16();
                _ = reader.ReadInt16(); // workstation name max length
                var workstationBufferOffset = reader.ReadInt32();

                _ = reader.ReadInt64(); // version

                if ((this.Flags & NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) > 0)
                {
                    reader.BaseStream.Seek(domainNameBufferOffset, SeekOrigin.Begin);

                    this.DomainName = Encoding.ASCII.GetString(reader.ReadBytes(domainNameLength));
                }

                if ((this.Flags & NtlmNegotiateFlag.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) > 0)
                {
                    reader.BaseStream.Seek(workstationBufferOffset, SeekOrigin.Begin);

                    this.Workstation = Encoding.ASCII.GetString(reader.ReadBytes(workstationLength));
                }
            }
            finally
            {
                reader?.Dispose();
            }
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
}