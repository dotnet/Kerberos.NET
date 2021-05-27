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
    public partial class KrbEncTicketPart
    {
        /*
          EncTicketPart   ::= [APPLICATION 3] SEQUENCE {
                  flags                   [0] TicketFlags,
                  key                     [1] EncryptionKey,
                  crealm                  [2] Realm,
                  cname                   [3] PrincipalName,
                  transited               [4] TransitedEncoding,
                  authtime                [5] KerberosTime,
                  starttime               [6] KerberosTime OPTIONAL,
                  endtime                 [7] KerberosTime,
                  renew-till              [8] KerberosTime OPTIONAL,
                  caddr                   [9] HostAddresses OPTIONAL,
                  authorization-data      [10] AuthorizationData OPTIONAL
          }
         */
    
        public TicketFlags Flags { get; set; }
        public KrbEncryptionKey Key { get; set; }
  
        public string CRealm { get; set; }
  
        public KrbPrincipalName CName { get; set; }
  
        public KrbTransitedEncoding Transited { get; set; }
  
        public DateTimeOffset AuthTime { get; set; }
  
        public DateTimeOffset? StartTime { get; set; }
  
        public DateTimeOffset EndTime { get; set; }
  
        public DateTimeOffset? RenewTill { get; set; }
  
        public KrbHostAddress[] CAddr { get; set; }
  
        public KrbAuthorizationData[] AuthorizationData { get; set; }
  
        // Encoding methods
        internal void Encode(AsnWriter writer)
        {
            EncodeApplication(writer, ApplicationTag);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteBitString(Flags.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            Key?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, CRealm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            CName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            Transited?.Encode(writer);
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

            if (Asn1Extension.HasValue(CAddr))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
                writer.PushSequence();
            
                for (int i = 0; i < CAddr.Length; i++)
                {
                    CAddr[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            }
  

            if (Asn1Extension.HasValue(AuthorizationData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
                writer.PushSequence();
            
                for (int i = 0; i < AuthorizationData.Length; i++)
                {
                    AuthorizationData[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            }
  
            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            this.Encode(writer, Asn1Tag.Sequence);
            
            writer.PopSequence(tag);
        }       
        
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 3);
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbEncTicketPart DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbEncTicketPart decoded;
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
        
        internal static KrbEncTicketPart DecodeApplication<T>(AsnReader reader, out T decoded)
          where T: KrbEncTicketPart, new()
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
        
        internal static KrbEncTicketPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbEncTicketPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbEncTicketPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbEncTicketPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbEncTicketPart, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            DecodeApplication(reader, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbEncTicketPart, new()
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

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpFlags))
            {
                decoded.Flags = (TicketFlags)tmpFlags.AsLong();
            }
            else
            {
                decoded.Flags = (TicketFlags)explicitReader.ReadBitString(out _).AsLong();
            }


            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            KrbEncryptionKey.Decode<KrbEncryptionKey>(explicitReader, out KrbEncryptionKey tmpKey);
            decoded.Key = tmpKey;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            decoded.CRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpCName);
            decoded.CName = tmpCName;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            KrbTransitedEncoding.Decode<KrbTransitedEncoding>(explicitReader, out KrbTransitedEncoding tmpTransited);
            decoded.Transited = tmpTransited;

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

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));                
            
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

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 10));                
            
                // Decode SEQUENCE OF for AuthorizationData
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbAuthorizationData>();
                    KrbAuthorizationData tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbAuthorizationData.Decode<KrbAuthorizationData>(collectionReader, out KrbAuthorizationData tmp);
                        tmpItem = tmp; 
                        tmpList.Add(tmpItem);
                    }

                    decoded.AuthorizationData = tmpList.ToArray();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
