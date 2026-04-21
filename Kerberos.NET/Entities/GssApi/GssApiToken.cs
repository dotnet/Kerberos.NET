// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public class GssApiToken
    {
        public ReadOnlyMemory<byte> Token { get; private set; }

        public Oid ThisMech { get; private set; }

        public MessageType MessageType { get; private set; }

        // GSSAPI-Token ::= [APPLICATION 0] IMPLICIT SEQUENCE {
        //      thisMech MechType,
        //      innerToken ANY DEFINED BY thisMech
        //
        //      // contents mechanism-specific
        //      // ASN.1 structure not required
        // }
        //
        // Token               TOK_ID Value in Hex
        // - - - - - - - - - - - - - - - - - - - - -
        // KRB_AP_REQ            01 00
        // KRB_AP_REP            02 00
        // KRB_ERROR             03 00
        // IA_KERB               05 01

        private static readonly Asn1Tag ApplicationTag = new(TagClass.Application, 0);

        private static readonly ReadOnlyDictionary<MessageType, short> MessageTokenTypes
            = new(new Dictionary<MessageType, short>()
        {
            { MessageType.KRB_AP_REQ, 0x01 },
            { MessageType.KRB_AP_REP, 0x02 },
            { MessageType.KRB_ERROR, 0x03 },
            { MessageType.IAKERB_HEADER, 0x0105 },
        });

        private static readonly ReadOnlyDictionary<short, MessageType> TokenMessageTypes
            = new(MessageTokenTypes.ToDictionary(t => t.Value, t => t.Key));

        private static readonly Oid IAKerbOid = new(MechType.IAKerb);

        public static ReadOnlyMemory<byte> EncodeIAKerbProxy(IAKerbHeader header, ReadOnlyMemory<byte> kerbMessage)
        {
            if (header == null)
            {
                throw new ArgumentNullException(nameof(header));
            }

            // Encode the OID using an AsnWriter
            byte[] oidEncoded;

            using (var oidWriter = new AsnWriter(AsnEncodingRules.DER))
            {
                oidWriter.WriteObjectIdentifier(IAKerbOid);
                oidEncoded = oidWriter.Encode();
            }

            // TOK_ID for IAKERB_PROXY: 05 01
            var tokenTypeBytes = new byte[] { 0x05, 0x01 };
            var headerEncoded = header.Encode();

            // Calculate total inner content length
            int innerLength = oidEncoded.Length + tokenTypeBytes.Length + headerEncoded.Length + kerbMessage.Length;

            // Build the APPLICATION 0 IMPLICIT SEQUENCE manually
            // Tag = 0x60, then DER length, then content
            using (var stream = new System.IO.MemoryStream())
            {
                stream.WriteByte(0x60); // APPLICATION 0 CONSTRUCTED
                WriteDerLength(stream, innerLength);
                stream.Write(oidEncoded, 0, oidEncoded.Length);
                stream.Write(tokenTypeBytes, 0, tokenTypeBytes.Length);

                var headerBytes = headerEncoded.ToArray();
                stream.Write(headerBytes, 0, headerBytes.Length);

                if (kerbMessage.Length > 0)
                {
                    var msgBytes = kerbMessage.ToArray();
                    stream.Write(msgBytes, 0, msgBytes.Length);
                }

                return stream.ToArray();
            }
        }

        private static void WriteDerLength(System.IO.MemoryStream stream, int length)
        {
            if (length < 0x80)
            {
                stream.WriteByte((byte)length);
            }
            else if (length <= 0xFF)
            {
                stream.WriteByte(0x81);
                stream.WriteByte((byte)length);
            }
            else if (length <= 0xFFFF)
            {
                stream.WriteByte(0x82);
                stream.WriteByte((byte)(length >> 8));
                stream.WriteByte((byte)length);
            }
            else if (length <= 0xFFFFFF)
            {
                stream.WriteByte(0x83);
                stream.WriteByte((byte)(length >> 16));
                stream.WriteByte((byte)(length >> 8));
                stream.WriteByte((byte)length);
            }
            else
            {
                stream.WriteByte(0x84);
                stream.WriteByte((byte)(length >> 24));
                stream.WriteByte((byte)(length >> 16));
                stream.WriteByte((byte)(length >> 8));
                stream.WriteByte((byte)length);
            }
        }

        public static ReadOnlyMemory<byte> Encode(Oid oid, NegotiationToken token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                writer.WriteObjectIdentifier(oid);

                writer.WriteEncodedValue(token.Encode().Span);

                writer.PopSequence(ApplicationTag);

                return writer.Encode();
            }
        }

        public static ReadOnlyMemory<byte> Encode(Oid oid, KrbApReq krbApReq)
            => Encode<KrbApReq>(oid, krbApReq);

        public static ReadOnlyMemory<byte> Encode<T>(Oid oid, IAsn1ApplicationEncoder<T> body)
        {
            if (body == null)
            {
                throw new ArgumentNullException(nameof(body));
            }

            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                writer.WriteObjectIdentifier(oid);

                if (!MessageTokenTypes.TryGetValue(body.MessageType, out short tokenType))
                {
                    throw new UnknownMechTypeException();
                }

                Span<byte> tokenTypeBytes = stackalloc byte[2];

                BinaryPrimitives.WriteInt16LittleEndian(tokenTypeBytes, tokenType);

                writer.WriteEncodedValue(tokenTypeBytes);

                writer.WriteEncodedValue(body.EncodeApplication().Span);

                writer.PopSequence(ApplicationTag);

                return writer.Encode();
            }
        }

        public static GssApiToken Decode(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var sequenceReader = reader.ReadSequence(ApplicationTag);

            var token = new GssApiToken() { ThisMech = sequenceReader.ReadObjectIdentifier() };

            // this is a frustrating format -- it starts off as an ASN.1 encoded-thing
            // but values after thisMech don't have to be ASN.1 encoded, which means
            // you can't rely on the decoder to detect a single blob of next data
            //
            // as such this is still probably an incorrect way to parse the message

            while (sequenceReader.HasData)
            {
                var peek = sequenceReader.PeekRawBytes(2);
                var peekShort = BinaryPrimitives.ReadInt16LittleEndian(peek.Span);

                if (TokenMessageTypes.TryGetValue(peekShort, out MessageType type))
                {
                    token.MessageType = type;
                    token.Token = sequenceReader.ReadRawBytes(sequenceReader.RemainingBytes).Slice(2);
                    continue;
                }

                var read = sequenceReader.ReadEncodedValue();
                var readShort = BinaryPrimitives.ReadInt16LittleEndian(read.Span.Slice(0, 2));

                if (TokenMessageTypes.TryGetValue(readShort, out type))
                {
                    token.MessageType = type;
                    token.Token = read.Slice(2);
                }
                else
                {
                    token.Token = read;
                }
            }

            return token;
        }
    }
}
