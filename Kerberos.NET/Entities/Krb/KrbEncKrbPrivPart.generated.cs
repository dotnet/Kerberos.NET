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
    public partial class KrbEncKrbPrivPart
    {
        /*
		  EncKrbPrivPart  ::= [APPLICATION 28] SEQUENCE {
				  user-data       [0] OCTET STRING,
				  timestamp       [1] KerberosTime OPTIONAL,
				  usec            [2] Microseconds OPTIONAL,
				  seq-number      [3] UInt32 OPTIONAL,
				  s-address       [4] HostAddress ( sender's addr ),
				  r-address       [5] HostAddress OPTIONAL ( recip's addr )
          }
         */
    
        public ReadOnlyMemory<byte> UserData { get; set; }
  
        public DateTimeOffset? Timestamp { get; set; }
  
        public int? Usec { get; set; }
  
        public int? SeqNumber { get; set; }
  
        public KrbHostAddress SAddress { get; set; }
  
        public KrbHostAddress RAddress { get; set; }
  
        // Encoding methods
        internal void Encode(AsnWriter writer)
        {
            EncodeApplication(writer, ApplicationTag);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteOctetString(UserData.Span);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (Asn1Extension.HasValue(Timestamp))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteGeneralizedTime(Timestamp.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }

            if (Asn1Extension.HasValue(Usec))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                writer.WriteInteger(Usec.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            if (Asn1Extension.HasValue(SeqNumber))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteInteger(SeqNumber.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            SAddress?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));

            if (Asn1Extension.HasValue(RAddress))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
                RAddress?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            }
            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            this.Encode(writer, Asn1Tag.Sequence);
            
            writer.PopSequence(tag);
        }       
        
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 28);
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbEncKrbPrivPart DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbEncKrbPrivPart decoded;
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
        
        internal static KrbEncKrbPrivPart DecodeApplication<T>(AsnReader reader, out T decoded)
          where T: KrbEncKrbPrivPart, new()
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
        
        internal static KrbEncKrbPrivPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbEncKrbPrivPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbEncKrbPrivPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbEncKrbPrivPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbEncKrbPrivPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            DecodeApplication(reader, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbEncKrbPrivPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpUserData))
            {
                decoded.UserData = tmpUserData;
            }
            else
            {
                decoded.UserData = explicitReader.ReadOctetString();
            }

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            
                decoded.Timestamp = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                if (explicitReader.TryReadInt32(out int tmpUsec))
                {
                    decoded.Usec = tmpUsec;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            
                if (explicitReader.TryReadInt32(out int tmpSeqNumber))
                {
                    decoded.SeqNumber = tmpSeqNumber;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            KrbHostAddress.Decode<KrbHostAddress>(explicitReader, out KrbHostAddress tmpSAddress);
            decoded.SAddress = tmpSAddress;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 5)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));                
            
                KrbHostAddress.Decode<KrbHostAddress>(explicitReader, out KrbHostAddress tmpRAddress);
                decoded.RAddress = tmpRAddress;
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
