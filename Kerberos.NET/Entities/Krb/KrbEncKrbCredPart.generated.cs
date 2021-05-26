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
    public partial class KrbEncKrbCredPart
    {
        /*
          EncKrbCredPart  ::= [APPLICATION 29] SEQUENCE {
                  ticket-info     [0] SEQUENCE OF KrbCredInfo,
                  nonce           [1] UInt32 OPTIONAL,
                  timestamp       [2] KerberosTime OPTIONAL,
                  usec            [3] Microseconds OPTIONAL,
                  s-address       [4] HostAddress OPTIONAL,
                  r-address       [5] HostAddress OPTIONAL
          }
         */
    
        public KrbCredInfo[] TicketInfo { get; set; }
  
        public int? Nonce { get; set; }
  
        public DateTimeOffset? Timestamp { get; set; }
  
        public int? USec { get; set; }
  
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
            writer.PushSequence();
            
            for (int i = 0; i < TicketInfo.Length; i++)
            {
                TicketInfo[i]?.Encode(writer); 
            }

            writer.PopSequence();

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (Asn1Extension.HasValue(Nonce))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteInteger(Nonce.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }

            if (Asn1Extension.HasValue(Timestamp))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                writer.WriteGeneralizedTime(Timestamp.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            if (Asn1Extension.HasValue(USec))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteInteger(USec.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }

            if (Asn1Extension.HasValue(SAddress))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                SAddress?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            }

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
        
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 29);
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbEncKrbCredPart DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbEncKrbCredPart decoded;
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
        
        internal static KrbEncKrbCredPart DecodeApplication<T>(AsnReader reader, out T decoded)
          where T: KrbEncKrbCredPart, new()
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
        
        internal static KrbEncKrbCredPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbEncKrbCredPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbEncKrbCredPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbEncKrbCredPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbEncKrbCredPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            DecodeApplication(reader, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbEncKrbCredPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            // Decode SEQUENCE OF for TicketInfo
            {
                collectionReader = explicitReader.ReadSequence();
                var tmpList = new List<KrbCredInfo>();
                KrbCredInfo tmpItem;

                while (collectionReader.HasData)
                {
                    KrbCredInfo.Decode<KrbCredInfo>(collectionReader, out KrbCredInfo tmp);
                    tmpItem = tmp; 
                    tmpList.Add(tmpItem);
                }

                decoded.TicketInfo = tmpList.ToArray();
            }

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            
                if (explicitReader.TryReadInt32(out int tmpNonce))
                {
                    decoded.Nonce = tmpNonce;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                decoded.Timestamp = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            
                if (explicitReader.TryReadInt32(out int tmpUSec))
                {
                    decoded.USec = tmpUSec;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));                
            
                KrbHostAddress.Decode<KrbHostAddress>(explicitReader, out KrbHostAddress tmpSAddress);
                decoded.SAddress = tmpSAddress;
                explicitReader.ThrowIfNotEmpty();
            }

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
