// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

// This is a generated file.
// The generation template has been modified from .NET Runtime implementation

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaPkAsReq
    {
        public ReadOnlyMemory<byte> SignedAuthPack { get; set; }
  
        public KrbExternalPrincipalIdentifier[] TrustedCertifiers { get; set; }
  
        public ReadOnlyMemory<byte>? KdcPkId { get; set; }
  
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
            
            writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 0), SignedAuthPack.Span);

            if (Asn1Extension.HasValue(TrustedCertifiers))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.PushSequence();
            
                for (int i = 0; i < TrustedCertifiers.Length; i++)
                {
                    TrustedCertifiers[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }
  

            if (Asn1Extension.HasValue(KdcPkId))
            {
                writer.WriteOctetString(new Asn1Tag(TagClass.ContextSpecific, 2), KdcPkId.Value.Span);
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
        
        public static KrbPaPkAsReq Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbPaPkAsReq Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbPaPkAsReq Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbPaPkAsReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbPaPkAsReq Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbPaPkAsReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbPaPkAsReq, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbPaPkAsReq, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            

            if (sequenceReader.TryReadPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 0), out ReadOnlyMemory<byte> tmpSignedAuthPack))
            {
                decoded.SignedAuthPack = tmpSignedAuthPack;
            }
            else
            {
                decoded.SignedAuthPack = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
            }
            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            
                // Decode SEQUENCE OF for TrustedCertifiers
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbExternalPrincipalIdentifier>();
                    KrbExternalPrincipalIdentifier tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbExternalPrincipalIdentifier.Decode<KrbExternalPrincipalIdentifier>(collectionReader, out KrbExternalPrincipalIdentifier tmp);
                        tmpItem = tmp; 
                        tmpList.Add(tmpItem);
                    }

                    decoded.TrustedCertifiers = tmpList.ToArray();
                }
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {

                if (sequenceReader.TryReadPrimitiveOctetStringBytes(new Asn1Tag(TagClass.ContextSpecific, 2), out ReadOnlyMemory<byte> tmpKdcPkId))
                {
                    decoded.KdcPkId = tmpKdcPkId;
                }
                else
                {
                    decoded.KdcPkId = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 2));
                }
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
