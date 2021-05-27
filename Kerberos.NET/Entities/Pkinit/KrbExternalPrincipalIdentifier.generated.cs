// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

// This is a generated file.
// The generation template has been modified from .NET Runtime implementation

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbExternalPrincipalIdentifier
    {
        /*
          ExternalPrincipalIdentifier ::= SEQUENCE {
            subjectName            [0] IMPLICIT OCTET STRING OPTIONAL,
          		   - - Contains a PKIX type Name encoded according to
          		   - - [RFC3280].
          		   - - Identifies the certificate subject by the
          		   - - distinguished subject name.
          		   - - REQUIRED when there is a distinguished subject
          		   - - name present in the certificate.
           issuerAndSerialNumber   [1] IMPLICIT OCTET STRING OPTIONAL,
          		   - - Contains a CMS type IssuerAndSerialNumber encoded
          		   - - according to [RFC3852].
          		   - - Identifies a certificate of the subject.
          		   - - REQUIRED for TD-INVALID-CERTIFICATES and
          		   - - TD-TRUSTED-CERTIFIERS.
           subjectKeyIdentifier    [2] IMPLICIT OCTET STRING OPTIONAL,
          		   - - Identifies the subject's public key by a key
          		   - - identifier.  When an X.509 certificate is
          		   - - referenced, this key identifier matches the X.509
          		   - - subjectKeyIdentifier extension value.  When other
          		   - - certificate formats are referenced, the documents
          		   - - that specify the certificate format and their use
          		   - - with the CMS must include details on matching the
          		   - - key identifier to the appropriate certificate
          		   - - field.
          		   - - RECOMMENDED for TD-TRUSTED-CERTIFIERS.
            ...
          }
         */
    
        public ReadOnlyMemory<byte>? SubjectName { get; set; }
  
        public ReadOnlyMemory<byte>? IssuerAndSerialNumber { get; set; }
  
        public ReadOnlyMemory<byte>? SubjectKeyIdentifier { get; set; }
  
        // Encoding methods
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
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbExternalPrincipalIdentifier, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

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
