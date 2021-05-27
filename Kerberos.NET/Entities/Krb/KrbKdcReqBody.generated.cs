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
    public partial class KrbKdcReqBody
    {
        /*
          KDC-REQ-BODY    ::= SEQUENCE {
                  kdc-options             [0] KDCOptions,
                  cname                   [1] PrincipalName OPTIONAL
                  realm                   [2] Realm
                  sname                   [3] PrincipalName OPTIONAL,
                  from                    [4] KerberosTime OPTIONAL,
                  till                    [5] KerberosTime,
                  rtime                   [6] KerberosTime OPTIONAL,
                  nonce                   [7] UInt32,
                  etype                   [8] SEQUENCE OF Int32 
                  addresses               [9] HostAddresses OPTIONAL,
                  enc-authorization-data  [10] EncryptedData OPTIONAL
                  additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
          }
         */
    
        public KdcOptions KdcOptions { get; set; }
        public KrbPrincipalName CName { get; set; }
  
        public string Realm { get; set; }
  
        public KrbPrincipalName SName { get; set; }
  
        public DateTimeOffset? From { get; set; }
  
        public DateTimeOffset Till { get; set; }
  
        public DateTimeOffset? RTime { get; set; }
  
        public int Nonce { get; set; }
  
        public EncryptionType[] EType { get; set; }
  
        public KrbHostAddress[] Addresses { get; set; }
  
        public KrbEncryptedData EncAuthorizationData { get; set; }
  
        public KrbTicket[] AdditionalTickets { get; set; }
  
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
            writer.WriteBitString(KdcOptions.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (Asn1Extension.HasValue(CName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                CName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (Asn1Extension.HasValue(SName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                SName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }

            if (Asn1Extension.HasValue(From))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                writer.WriteGeneralizedTime(From.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteGeneralizedTime(Till);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (Asn1Extension.HasValue(RTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.WriteGeneralizedTime(RTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            writer.WriteInteger(Nonce);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            writer.PushSequence();
            
            for (int i = 0; i < EType.Length; i++)
            {
                writer.WriteInteger((long)EType[i]); 
            }

            writer.PopSequence();

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));

            if (Asn1Extension.HasValue(Addresses))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
                writer.PushSequence();
            
                for (int i = 0; i < Addresses.Length; i++)
                {
                    Addresses[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            }
  

            if (Asn1Extension.HasValue(EncAuthorizationData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
                EncAuthorizationData?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            }

            if (Asn1Extension.HasValue(AdditionalTickets))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
                writer.PushSequence();
            
                for (int i = 0; i < AdditionalTickets.Length; i++)
                {
                    AdditionalTickets[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
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
        
        public static KrbKdcReqBody Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbKdcReqBody Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbKdcReqBody Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbKdcReqBody decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbKdcReqBody Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbKdcReqBody decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbKdcReqBody, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbKdcReqBody, new()
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

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpKdcOptions))
            {
                decoded.KdcOptions = (KdcOptions)tmpKdcOptions.AsLong();
            }
            else
            {
                decoded.KdcOptions = (KdcOptions)explicitReader.ReadBitString(out _).AsLong();
            }


            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            
                KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpCName);
                decoded.CName = tmpCName;
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            
                KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpSName);
                decoded.SName = tmpSName;
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));                
            
                decoded.From = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            decoded.Till = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));                
            
                decoded.RTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));

            if (!explicitReader.TryReadInt32(out int tmpNonce))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.Nonce = tmpNonce;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            // Decode SEQUENCE OF for EType
            {
                collectionReader = explicitReader.ReadSequence();
                var tmpList = new List<EncryptionType>();
                EncryptionType tmpItem;

                while (collectionReader.HasData)
                {

                    if (!collectionReader.TryReadInt32(out EncryptionType tmp))
                    {
                        collectionReader.ThrowIfNotEmpty();
                    }
            
            tmpItem = tmp; 
                    tmpList.Add(tmpItem);
                }

                decoded.EType = tmpList.ToArray();
            }

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));                
            
                // Decode SEQUENCE OF for Addresses
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

                    decoded.Addresses = tmpList.ToArray();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 10));                
            
                KrbEncryptedData.Decode<KrbEncryptedData>(explicitReader, out KrbEncryptedData tmpEncAuthorizationData);
                decoded.EncAuthorizationData = tmpEncAuthorizationData;
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 11)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 11));                
            
                // Decode SEQUENCE OF for AdditionalTickets
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbTicket>();
                    KrbTicket tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbTicket.Decode<KrbTicket>(collectionReader, out KrbTicket tmp);
                        tmpItem = tmp; 
                        tmpList.Add(tmpItem);
                    }

                    decoded.AdditionalTickets = tmpList.ToArray();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
