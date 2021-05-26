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
    public partial class KrbFastFinished
    {
        /*
            KrbFastFinished ::= SEQUENCE {
                timestamp       [0] KerberosTime,
                usec            [1] Microseconds,
                    - - timestamp and usec represent the time on the KDC when
                    - - the reply was generated.
                crealm          [2] Realm,
                cname           [3] PrincipalName,
                    - - Contains the client realm and the client name.
                ticket-checksum [4] Checksum,
                    - - checksum of the ticket in the KDC-REP using the armor
                    - - and the key usage is KEY_USAGE_FAST_FINISH.
                    - - The checksum type is the required checksum type
                    - - of the armor key.
                ...
            }
         */
    
        public DateTimeOffset Timestamp { get; set; }
  
        public int USec { get; set; }
  
        public string CRealm { get; set; }
  
        public KrbPrincipalName CName { get; set; }
  
        public KrbChecksum TicketChecksum { get; set; }
  
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
            writer.WriteGeneralizedTime(Timestamp);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteInteger(USec);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, CRealm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            CName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            TicketChecksum?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
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
        
        public static KrbFastFinished Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbFastFinished Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbFastFinished Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbFastFinished decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbFastFinished Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbFastFinished decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbFastFinished, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbFastFinished, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            decoded.Timestamp = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (!explicitReader.TryReadInt32(out int tmpUSec))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.USec = tmpUSec;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            decoded.CRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpCName);
            decoded.CName = tmpCName;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            KrbChecksum.Decode<KrbChecksum>(explicitReader, out KrbChecksum tmpTicketChecksum);
            decoded.TicketChecksum = tmpTicketChecksum;

            explicitReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
