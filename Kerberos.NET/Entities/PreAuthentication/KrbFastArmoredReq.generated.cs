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
    public partial class KrbFastArmoredReq
    {
        /*
          KrbFastArmoredReq ::= SEQUENCE {
              armor        [0] KrbFastArmor OPTIONAL,
                  - - Contains the armor that identifies the armor key.
                  - - MUST be present in AS-REQ.
              req-checksum [1] Checksum,
                  - - For AS, contains the checksum performed over the type
                  - - KDC-REQ-BODY for the req-body field of the KDC-REQ
                  - - structure;
                  - - For TGS, contains the checksum performed over the type
                  - - AP-REQ in the PA-TGS-REQ padata.
                  - - The checksum key is the armor key, the checksum
                  - - type is the required checksum type for the enctype of
                  - - the armor key, and the key usage number is
                  - - KEY_USAGE_FAST_REQ_CHKSUM.
              enc-fast-req [2] EncryptedData, - - KrbFastReq - -
                  - - The encryption key is the armor key, and the key usage
                  - - number is KEY_USAGE_FAST_ENC.
              ...
          }
         */
    
        public KrbFastArmor Armor { get; set; }
  
        public KrbChecksum RequestChecksum { get; set; }
  
        public KrbEncryptedData EncryptedFastRequest { get; set; }
  
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
            

            if (Asn1Extension.HasValue(Armor))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                Armor?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            RequestChecksum?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            EncryptedFastRequest?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
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
        
        public static KrbFastArmoredReq Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbFastArmoredReq Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbFastArmoredReq Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbFastArmoredReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbFastArmoredReq Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbFastArmoredReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbFastArmoredReq, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbFastArmoredReq, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));                
            
                KrbFastArmor.Decode<KrbFastArmor>(explicitReader, out KrbFastArmor tmpArmor);
                decoded.Armor = tmpArmor;
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            KrbChecksum.Decode<KrbChecksum>(explicitReader, out KrbChecksum tmpRequestChecksum);
            decoded.RequestChecksum = tmpRequestChecksum;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            KrbEncryptedData.Decode<KrbEncryptedData>(explicitReader, out KrbEncryptedData tmpEncryptedFastRequest);
            decoded.EncryptedFastRequest = tmpEncryptedFastRequest;

            explicitReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
