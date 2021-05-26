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
    public partial class KrbEncApRepPart
    {
        /*
          EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
                  ctime           [0] KerberosTime,
                  cusec           [1] Microseconds,
                  subkey          [2] EncryptionKey OPTIONAL,
                  seq-number      [3] UInt32 OPTIONAL
          }
         */
    
        public DateTimeOffset CTime { get; set; }
  
        public int CuSec { get; set; }
  
        public KrbEncryptionKey SubSessionKey { get; set; }
  
        public int? SequenceNumber { get; set; }
  
        // Encoding methods
        internal void Encode(AsnWriter writer)
        {
            EncodeApplication(writer, ApplicationTag);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteGeneralizedTime(CTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteInteger(CuSec);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (Asn1Extension.HasValue(SubSessionKey))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                SubSessionKey?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            if (Asn1Extension.HasValue(SequenceNumber))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteInteger(SequenceNumber.Value);
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
        
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 27);
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbEncApRepPart DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbEncApRepPart decoded;
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
        
        internal static KrbEncApRepPart DecodeApplication<T>(AsnReader reader, out T decoded)
          where T: KrbEncApRepPart, new()
        {
            var sequence = reader.ReadSequence(ApplicationTag);
          
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
         
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                EncodeApplication(writer, tag);

                return writer.EncodeAsMemory();
            }
        }
        
        internal static KrbEncApRepPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbEncApRepPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbEncApRepPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbEncApRepPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbEncApRepPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            DecodeApplication(reader, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbEncApRepPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            decoded.CTime = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (!explicitReader.TryReadInt32(out int tmpCuSec))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.CuSec = tmpCuSec;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                KrbEncryptionKey.Decode<KrbEncryptionKey>(explicitReader, out KrbEncryptionKey tmpSubSessionKey);
                decoded.SubSessionKey = tmpSubSessionKey;
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            
                if (explicitReader.TryReadInt32(out int tmpSequenceNumber))
                {
                    decoded.SequenceNumber = tmpSequenceNumber;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
