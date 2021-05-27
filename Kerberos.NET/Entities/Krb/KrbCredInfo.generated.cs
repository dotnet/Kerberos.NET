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
    public partial class KrbCredInfo
    {
        /*
          KrbCredInfo     ::= SEQUENCE {
                  key             [0] EncryptionKey,
                  prealm          [1] Realm OPTIONAL,
                  pname           [2] PrincipalName OPTIONAL,
                  flags           [3] TicketFlags OPTIONAL,
                  authtime        [4] KerberosTime OPTIONAL,
                  starttime       [5] KerberosTime OPTIONAL,
                  endtime         [6] KerberosTime OPTIONAL,
                  renew-till      [7] KerberosTime OPTIONAL,
                  srealm          [8] Realm OPTIONAL,
                  sname           [9] PrincipalName OPTIONAL,
                  caddr           [10] HostAddresses OPTIONAL
          }
         */
    
        public KrbEncryptionKey Key { get; set; }
  
        public string Realm { get; set; }
  
        public KrbPrincipalName PName { get; set; }
  
        public TicketFlags Flags { get; set; }
        public DateTimeOffset? AuthTime { get; set; }
  
        public DateTimeOffset? StartTime { get; set; }
  
        public DateTimeOffset? EndTime { get; set; }
  
        public DateTimeOffset? RenewTill { get; set; }
  
        public string SRealm { get; set; }
  
        public KrbPrincipalName SName { get; set; }
  
        public KrbAuthorizationData[] AuthorizationData { get; set; }
  
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

            if (Asn1Extension.HasValue(Realm))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }
  

            if (Asn1Extension.HasValue(PName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                PName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.WriteBitString(Flags.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            if (Asn1Extension.HasValue(AuthTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                writer.WriteGeneralizedTime(AuthTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            }

            if (Asn1Extension.HasValue(StartTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
                writer.WriteGeneralizedTime(StartTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            }

            if (Asn1Extension.HasValue(EndTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.WriteGeneralizedTime(EndTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }

            if (Asn1Extension.HasValue(RenewTill))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                writer.WriteGeneralizedTime(RenewTill.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            }

            if (Asn1Extension.HasValue(SRealm))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, SRealm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }
  

            if (Asn1Extension.HasValue(SName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
                SName?.Encode(writer);
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
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() => new ReadOnlyMemory<byte>();
         
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                EncodeApplication(writer, tag);

                return writer.EncodeAsMemory();
            }
        }
        
        public static KrbCredInfo Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbCredInfo Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbCredInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbCredInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbCredInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbCredInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbCredInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbCredInfo, new()
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

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            
                decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpPName);
                decoded.PName = tmpPName;
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpFlags))
            {
                decoded.Flags = (TicketFlags)tmpFlags.AsLong();
            }
            else
            {
                decoded.Flags = (TicketFlags)explicitReader.ReadBitString(out _).AsLong();
            }


            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));                
            
                decoded.AuthTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 5)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));                
            
                decoded.StartTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));                
            
                decoded.EndTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));                
            
                decoded.RenewTill = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));                
            
                decoded.SRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));                
            
                KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpSName);
                decoded.SName = tmpSName;
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
