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
    public partial class KrbEncKdcRepPart
    {
        public KrbEncryptionKey Key { get; set; }
  
        public KrbLastReq[] LastReq { get; set; }
  
        public int Nonce { get; set; }
  
        public DateTimeOffset? KeyExpiration { get; set; }
  
        public TicketFlags Flags { get; set; }
    
        public DateTimeOffset AuthTime { get; set; }
  
        public DateTimeOffset? StartTime { get; set; }
  
        public DateTimeOffset EndTime { get; set; }
  
        public DateTimeOffset? RenewTill { get; set; }
  
        public string Realm { get; set; }
  
        public KrbPrincipalName SName { get; set; }
  
        public KrbHostAddress[] CAddr { get; set; }
  
        public KrbMethodData EncryptedPaData { get; set; }
  
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
            Key?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence();
            
            for (int i = 0; i < LastReq.Length; i++)
            {
                LastReq[i]?.Encode(writer); 
            }

            writer.PopSequence();

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteInteger(Nonce);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (Asn1Extension.HasValue(KeyExpiration))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteGeneralizedTime(KeyExpiration.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.WriteBitString(Flags.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteGeneralizedTime(AuthTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (Asn1Extension.HasValue(StartTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.WriteGeneralizedTime(StartTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            writer.WriteGeneralizedTime(EndTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));

            if (Asn1Extension.HasValue(RenewTill))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                writer.WriteGeneralizedTime(RenewTill.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            SName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));

            if (Asn1Extension.HasValue(CAddr))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
                writer.PushSequence();
            
                for (int i = 0; i < CAddr.Length; i++)
                {
                    CAddr[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
            }
  

            if (Asn1Extension.HasValue(EncryptedPaData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 12));
                EncryptedPaData?.Encode(writer);
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
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() => new ReadOnlyMemory<byte>();
         
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                EncodeApplication(writer, tag);

                return writer.EncodeAsMemory();
            }
        }
        
        public static KrbEncKdcRepPart Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbEncKdcRepPart Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbEncKdcRepPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbEncKdcRepPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbEncKdcRepPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbEncKdcRepPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbEncKdcRepPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbEncKdcRepPart, new()
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
            KrbEncryptionKey.Decode<KrbEncryptionKey>(explicitReader, out KrbEncryptionKey tmpKey);
            decoded.Key = tmpKey;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            // Decode SEQUENCE OF for LastReq
            {
                collectionReader = explicitReader.ReadSequence();
                var tmpList = new List<KrbLastReq>();
                KrbLastReq tmpItem;

                while (collectionReader.HasData)
                {
                    KrbLastReq.Decode<KrbLastReq>(collectionReader, out KrbLastReq tmp);
                    tmpItem = tmp; 
                    tmpList.Add(tmpItem);
                }

                decoded.LastReq = tmpList.ToArray();
            }

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
            
                decoded.KeyExpiration = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpFlags))
            {
                decoded.Flags = (TicketFlags)tmpFlags.AsLong();
            }
            else
            {
                decoded.Flags = (TicketFlags)explicitReader.ReadBitString(out _).AsLong();
            }


            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            decoded.AuthTime = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));                
            
                decoded.StartTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            decoded.EndTime = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));                
            
                decoded.RenewTill = explicitReader.ReadGeneralizedTime();
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
            
                // Decode SEQUENCE OF for CAddr
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbHostAddress>();
                    KrbHostAddress tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbHostAddress.Decode<KrbHostAddress>(collectionReader, out KrbHostAddress tmp);
                        tmpItem = tmp; 
                        tmpList.Add(tmpItem);
                    }

                    decoded.CAddr = tmpList.ToArray();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 12)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 12));                
            
                KrbMethodData.Decode<KrbMethodData>(explicitReader, out KrbMethodData tmpEncryptedPaData);
                decoded.EncryptedPaData = tmpEncryptedPaData;
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
