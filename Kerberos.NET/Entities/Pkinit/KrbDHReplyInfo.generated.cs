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
    public partial class KrbDHReplyInfo
    {
        /*
          DHRepInfo ::= SEQUENCE {
            dhSignedData            [0] IMPLICIT OCTET STRING,
          		   - - Contains a CMS type ContentInfo encoded according
          		   - - to [RFC3852].
          		   - - The contentType field of the type ContentInfo is
          		   - - id-signedData (1.2.840.113549.1.7.2), and the
          		   - - content field is a SignedData.
          		   - - The eContentType field for the type SignedData is
          		   - - id-pkinit-DHKeyData (1.3.6.1.5.2.3.2), and the
          		   - - eContent field contains the DER encoding of the
          		   - - type KDCDHKeyInfo.
          		   - - KDCDHKeyInfo is defined below.
            serverDHNonce           [1] DHNonce OPTIONAL,
          		   - - Present if and only if dhKeyExpiration is
          		   - - present.
            ...
          }
         */
    
        public ReadOnlyMemory<byte> DHSignedData { get; set; }
  
        public ReadOnlyMemory<byte>? ServerDHNonce { get; set; }
  
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
            
            writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), DHSignedData.Span);

            if (Asn1Extension.HasValue(ServerDHNonce))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteOctetString(ServerDHNonce.Value.Span);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
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
        
        public static KrbDHReplyInfo Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbDHReplyInfo Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbDHReplyInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbDHReplyInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbDHReplyInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbDHReplyInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbDHReplyInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbDHReplyInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            

            if (sequenceReader.TryReadPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpDHSignedData))
            {
                decoded.DHSignedData = tmpDHSignedData;
            }
            else
            {
                decoded.DHSignedData = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
            }
            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            

                if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpServerDHNonce))
                {
                    decoded.ServerDHNonce = tmpServerDHNonce;
                }
                else
                {
                    decoded.ServerDHNonce = explicitReader.ReadOctetString();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
