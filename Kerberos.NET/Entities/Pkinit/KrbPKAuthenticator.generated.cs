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
    public partial class KrbPKAuthenticator
    {
        /*
          PKAuthenticator ::= SEQUENCE {
            cusec                   [0] INTEGER (0..999999),
            ctime                   [1] KerberosTime,
          		   - - cusec and ctime are used as in [RFC4120], for
          		   - - replay prevention.
            nonce                   [2] INTEGER (0..4294967295),
          		   - - Chosen randomly; this nonce does not need to
          		   - - match with the nonce in the KDC-REQ-BODY.
            paChecksum              [3] OCTET STRING OPTIONAL,
          		   - - MUST be present.
          		   - - Contains the SHA1 checksum, performed over
          		   - - KDC-REQ-BODY.
            ...
          }
         */
    
        public int CuSec { get; set; }
  
        public DateTimeOffset CTime { get; set; }
  
        public int Nonce { get; set; }
  
        public ReadOnlyMemory<byte>? PaChecksum { get; set; }
  
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
            writer.WriteInteger(CuSec);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteGeneralizedTime(CTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteInteger(Nonce);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (Asn1Extension.HasValue(PaChecksum))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteOctetString(PaChecksum.Value.Span);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
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
        
        public static KrbPKAuthenticator Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbPKAuthenticator Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbPKAuthenticator Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbPKAuthenticator decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbPKAuthenticator Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbPKAuthenticator decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbPKAuthenticator, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbPKAuthenticator, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (!explicitReader.TryReadInt32(out int tmpCuSec))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.CuSec = tmpCuSec;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            decoded.CTime = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (!explicitReader.TryReadInt32(out int tmpNonce))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.Nonce = tmpNonce;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            

                if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpPaChecksum))
                {
                    decoded.PaChecksum = tmpPaChecksum;
                }
                else
                {
                    decoded.PaChecksum = explicitReader.ReadOctetString();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
