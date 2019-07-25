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
        // 		thisMech MechType,
        // 		innerToken ANY DEFINED BY thisMech
        // 
        // 		// contents mechanism-specific
        // 		// ASN.1 structure not required
        // }
        // 
        // Token               TOK_ID Value in Hex
        // - - - - - - - - - - - - - - - - - - - - -
        // KRB_AP_REQ            01 00
        // KRB_AP_REP            02 00
        // KRB_ERROR             03 00

        public static GssApiToken Decode(ReadOnlyMemory<byte> data)
        {
            var reader = new AsnReader(data, AsnEncodingRules.DER);

            var token = new GssApiToken();

            var sequenceReader = reader.ReadSequence(new Asn1Tag(TagClass.Application, 0));

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
