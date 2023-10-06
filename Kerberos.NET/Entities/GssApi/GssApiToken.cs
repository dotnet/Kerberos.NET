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
