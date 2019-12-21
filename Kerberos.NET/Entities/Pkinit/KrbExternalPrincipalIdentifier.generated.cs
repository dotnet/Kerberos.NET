// This is a generated file.
// This file is licensed as per the LICENSE file.
// The generation template has been modified from .NET Foundation implementation

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbExternalPrincipalIdentifier
    {
        public ReadOnlyMemory<byte>? SubjectName;
        public ReadOnlyMemory<byte>? IssuerAndSerialNumber;
        public ReadOnlyMemory<byte>? SubjectKeyIdentifier;
      
        public ReadOnlyMemory<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsMemory();
        }
        
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            

            if (Asn1Extension.HasValue(SubjectName))
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), SubjectName.Value.Span);
            }


            if (Asn1Extension.HasValue(IssuerAndSerialNumber))
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 1), IssuerAndSerialNumber.Value.Span);
            }


            if (Asn1Extension.HasValue(SubjectKeyIdentifier))
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 2), SubjectKeyIdentifier.Value.Span);
            }

            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            this.Encode(writer, Asn1Tag.Sequence);
            
            writer.PopSequence(tag);
        }       
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() => new ReadOnlyMemory<byte>();
         
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                EncodeApplication(writer, tag);

                return writer.EncodeAsMemory();
            }
        }
        
        public static KrbExternalPrincipalIdentifier Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbExternalPrincipalIdentifier Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbExternalPrincipalIdentifier Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbExternalPrincipalIdentifier decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbExternalPrincipalIdentifier Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbExternalPrincipalIdentifier decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbExternalPrincipalIdentifier, new()
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbExternalPrincipalIdentifier, new()
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new T();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {

                if (sequenceReader.TryReadPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpSubjectName))
                {
                    decoded.SubjectName = tmpSubjectName;
                }
                else
                {
                    decoded.SubjectName = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {

                if (sequenceReader.TryReadPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 1), out ReadOnlyMemory<byte> tmpIssuerAndSerialNumber))
                {
                    decoded.IssuerAndSerialNumber = tmpIssuerAndSerialNumber;
                }
                else
                {
                    decoded.IssuerAndSerialNumber = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 1));
                }

            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {

                if (sequenceReader.TryReadPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 2), out ReadOnlyMemory<byte> tmpSubjectKeyIdentifier))
                {
                    decoded.SubjectKeyIdentifier = tmpSubjectKeyIdentifier;
                }
                else
                {
                    decoded.SubjectKeyIdentifier = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 2));
                }

            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
