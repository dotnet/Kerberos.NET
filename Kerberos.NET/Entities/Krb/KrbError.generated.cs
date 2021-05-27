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
    public partial class KrbError
    {
        /*
          KRB-ERROR       ::= [APPLICATION 30] SEQUENCE {
                  pvno            [0] INTEGER (5),
                  msg-type        [1] INTEGER (30),
                  ctime           [2] KerberosTime OPTIONAL,
                  cusec           [3] Microseconds OPTIONAL,
                  stime           [4] KerberosTime,
                  susec           [5] Microseconds,
                  error-code      [6] Int32,
                  crealm          [7] Realm OPTIONAL,
                  cname           [8] PrincipalName OPTIONAL,
                  realm           [9] Realm ,
                  sname           [10] PrincipalName,
                  e-text          [11] KerberosString OPTIONAL,
                  e-data          [12] OCTET STRING OPTIONAL
          }
         */
    
        public int ProtocolVersionNumber { get; set; }
  
        public MessageType MessageType { get; set; }
    
        public DateTimeOffset? CTime { get; set; }
  
        public int? Cusec { get; set; }
  
        public DateTimeOffset STime { get; set; }
  
        public int Susc { get; set; }
  
        public KerberosErrorCode ErrorCode { get; set; }
    
        public string CRealm { get; set; }
  
        public KrbPrincipalName CName { get; set; }
  
        public string Realm { get; set; }
  
        public KrbPrincipalName SName { get; set; }
  
        public string EText { get; set; }
  
        public ReadOnlyMemory<byte>? EData { get; set; }
  
        // Encoding methods
        internal void Encode(AsnWriter writer)
        {
            EncodeApplication(writer, ApplicationTag);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteInteger(ProtocolVersionNumber);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteInteger((long)MessageType);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (Asn1Extension.HasValue(CTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                writer.WriteGeneralizedTime(CTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            if (Asn1Extension.HasValue(Cusec))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteInteger(Cusec.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.WriteGeneralizedTime(STime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteInteger(Susc);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            writer.WriteInteger((long)ErrorCode);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));

            if (Asn1Extension.HasValue(CRealm))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, CRealm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            }
  

            if (Asn1Extension.HasValue(CName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                CName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            SName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));

            if (Asn1Extension.HasValue(EText))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, EText);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
            }
  

            if (Asn1Extension.HasValue(EData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 12));
                writer.WriteOctetString(EData.Value.Span);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 12));
            }
            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            this.Encode(writer, Asn1Tag.Sequence);
            
            writer.PopSequence(tag);
        }       
        
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 30);
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbError DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbError decoded;
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
        
        internal static KrbError DecodeApplication<T>(AsnReader reader, out T decoded)
          where T: KrbError, new()
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
        
        internal static KrbError Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbError decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbError Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbError decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbError, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            DecodeApplication(reader, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbError, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (!explicitReader.TryReadInt32(out int tmpProtocolVersionNumber))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.ProtocolVersionNumber = tmpProtocolVersionNumber;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (!explicitReader.TryReadInt32(out MessageType tmpMessageType))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.MessageType = tmpMessageType;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                decoded.CTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            
                if (explicitReader.TryReadInt32(out int tmpCusec))
                {
                    decoded.Cusec = tmpCusec;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            decoded.STime = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (!explicitReader.TryReadInt32(out int tmpSusc))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.Susc = tmpSusc;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));

            if (!explicitReader.TryReadInt32(out KerberosErrorCode tmpErrorCode))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.ErrorCode = tmpErrorCode;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));                
            
                decoded.CRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));                
            
                KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpCName);
                decoded.CName = tmpCName;
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpSName);
            decoded.SName = tmpSName;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 11)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 11));                
            
                decoded.EText = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 12)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 12));                
            

                if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpEData))
                {
                    decoded.EData = tmpEData;
                }
                else
                {
                    decoded.EData = explicitReader.ReadOctetString();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
