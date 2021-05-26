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
    public partial class KrbKdcDHKeyInfo
    {
        /*
          KDCDHKeyInfo ::= SEQUENCE {
            subjectPublicKey        [0] BIT STRING,
          		   - - The KDC's DH public key.
          		   - - The DH public key value is encoded as a BIT
          		   - - STRING according to [RFC3279].
            nonce                   [1] INTEGER (0..4294967295),
          		   - - Contains the nonce in the pkAuthenticator field
          		   - - in the request if the DH keys are NOT reused,
          		   - - 0 otherwise.
            dhKeyExpiration         [2] KerberosTime OPTIONAL,
          		   - - Expiration time for KDC's key pair,
          		   - - present if and only if the DH keys are reused.
          		   - - If present, the KDC's DH public key MUST not be
          		   - - used past the point of this expiration time.
          		   - - If this field is omitted then the serverDHNonce
          		   - - field MUST also be omitted.
            ...
          }
         */
    
        public ReadOnlyMemory<byte> SubjectPublicKey { get; set; }
    
        public System.Numerics.BigInteger Nonce { get; set; }
  
        public DateTimeOffset? DHKeyExpiration { get; set; }
  
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
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteBitString(SubjectPublicKey.Span);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteInteger(Nonce);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (Asn1Extension.HasValue(DHKeyExpiration))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                writer.WriteGeneralizedTime(DHKeyExpiration.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
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
        
        public static KrbKdcDHKeyInfo Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbKdcDHKeyInfo Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbKdcDHKeyInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbKdcDHKeyInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbKdcDHKeyInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbKdcDHKeyInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbKdcDHKeyInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbKdcDHKeyInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpSubjectPublicKey))
            {
                decoded.SubjectPublicKey = tmpSubjectPublicKey;
            }
            else
            {
                decoded.SubjectPublicKey = explicitReader.ReadBitString(out _);
            }


            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            decoded.Nonce = explicitReader.ReadInteger();

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                decoded.DHKeyExpiration = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
