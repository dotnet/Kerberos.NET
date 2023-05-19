// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

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

        private static readonly Asn1Tag ApplicationTag = new(TagClass.Application, 0);

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
        {
            if (krbApReq == null)
            {
                throw new ArgumentNullException(nameof(krbApReq));
            }

            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(ApplicationTag);

                writer.WriteObjectIdentifier(oid);

                writer.WriteEncodedValue(new byte[] { 0x01, 0x0 });

                writer.WriteEncodedValue(krbApReq.EncodeApplication().Span);

                writer.PopSequence(ApplicationTag);

                return writer.Encode();
            }
        }

        public static GssApiToken Decode(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var token = new GssApiToken();

            var sequenceReader = reader.ReadSequence(ApplicationTag);

            token.ThisMech = sequenceReader.ReadObjectIdentifier();

            // this is a frustrating format -- it starts off as an ASN.1 encoded-thing
            // but values after thisMech don't have to be ASN.1 encoded, which means
            // you can't rely on the decoder to detect a single blob of next data
            //
            // as such this is still probably an incorrect way to parse the message

            while (sequenceReader.HasData)
            {
                var read = sequenceReader.ReadEncodedValue();

                if (sequenceReader.HasData)
                {
                    switch (read.Span[0])
                    {
                        case 0x01:
                            token.MessageType = MessageType.KRB_AP_REQ;
                            break;
                        case 0x02:
                            token.MessageType = MessageType.KRB_AP_REP;
                            break;
                        case 0x03:
                            token.MessageType = MessageType.KRB_ERROR;
                            break;
                    }
                }
                else
                {
                    token.Token = read;
                    break;
                }
            }

            return token;
        }
    }
}