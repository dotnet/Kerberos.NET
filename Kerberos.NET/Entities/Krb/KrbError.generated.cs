
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbError : IAsn1Encoder
    {
        public int ProtocolVersionNumer;
        public MessageType MessageType;
        public DateTimeOffset? CTime;
        public int? Cusec;
        public DateTimeOffset STime;
        public int Susc;
        public KerberosErrorCode ErrorCode;
        public string CRealm;
        public KrbPrincipalName CName;
        public string Realm;
        public KrbPrincipalName SName;
        public string EText;
        public ReadOnlyMemory<byte>? EData;
      
        public ReadOnlySpan<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsSpan();
        }
        
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteInteger(ProtocolVersionNumer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteInteger((long)MessageType);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (HasValue(CTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                writer.WriteGeneralizedTime(CTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }


            if (HasValue(Cusec))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteInteger(Cusec.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.WriteGeneralizedTime(STime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteInteger(Susc);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            writer.WriteInteger((long)ErrorCode);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));

            if (HasValue(CRealm))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, CRealm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            }


            if (HasValue(CName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                CName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            SName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));

            if (HasValue(EText))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, EText);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
            }


            if (HasValue(EData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 12));
                writer.WriteOctetString(EData.Value.Span);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 12));
            }

            writer.PopSequence(tag);
        }
        
        public static KrbError Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbError Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbError Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbError decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }
        
        object IAsn1Encoder.Decode(ReadOnlyMemory<byte> data) 
        {
            return Decode(data);
        }

        internal static KrbError Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbError decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbError decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out KrbError decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbError();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (!explicitReader.TryReadInt32(out decoded.ProtocolVersionNumer))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (!explicitReader.TryReadInt32(out decoded.MessageType))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                decoded.CTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

                if (explicitReader.TryReadInt32(out int tmpCusec))
                {
                    decoded.Cusec = tmpCusec;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            decoded.STime = explicitReader.ReadGeneralizedTime();
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (!explicitReader.TryReadInt32(out decoded.Susc))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));

            if (!explicitReader.TryReadInt32(out decoded.ErrorCode))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                decoded.CRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                KrbPrincipalName tmpCName;
                KrbPrincipalName.Decode(explicitReader, out tmpCName);
                decoded.CName = tmpCName;

                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            KrbPrincipalName.Decode(explicitReader, out decoded.SName);
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 11)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
                decoded.EText = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 12)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 12));

                if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpEData))
                {
                    decoded.EData = tmpEData;
                }
                else
                {
                    decoded.EData = explicitReader.ReadOctetString();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static bool HasValue(object thing) 
        {
            return thing != null;
        }
    }
}
