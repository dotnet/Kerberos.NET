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
    public partial class KrbAuthenticator
    {
        /*
          Authenticator   ::= [APPLICATION 2] SEQUENCE  {
                  authenticator-vno       [0] INTEGER (5),
                  crealm                  [1] Realm,
                  cname                   [2] PrincipalName,
                  cksum                   [3] Checksum OPTIONAL,
                  cusec                   [4] Microseconds,
                  ctime                   [5] KerberosTime,
                  subkey                  [6] EncryptionKey OPTIONAL,
                  seq-number              [7] UInt32 OPTIONAL,
                  authorization-data      [8] AuthorizationData OPTIONAL
          }
         */
    
        public int AuthenticatorVersionNumber { get; set; }
  
        public string Realm { get; set; }
  
        public KrbPrincipalName CName { get; set; }
  
        public KrbChecksum Checksum { get; set; }
  
        public int CuSec { get; set; }
  
        public DateTimeOffset CTime { get; set; }
  
        public KrbEncryptionKey Subkey { get; set; }
  
        public int? SequenceNumber { get; set; }
  
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
            writer.WriteInteger(AuthenticatorVersionNumber);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            CName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (Asn1Extension.HasValue(Checksum))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                Checksum?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.WriteInteger(CuSec);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteGeneralizedTime(CTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (Asn1Extension.HasValue(Subkey))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                Subkey?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }

            if (Asn1Extension.HasValue(SequenceNumber))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                writer.WriteInteger(SequenceNumber.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            }

            if (Asn1Extension.HasValue(AuthorizationData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                writer.PushSequence();
            
                for (int i = 0; i < AuthorizationData.Length; i++)
                {
                    AuthorizationData[i]?.Encode(writer); 
                }

                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }
  
            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            this.Encode(writer, Asn1Tag.Sequence);
            
            writer.PopSequence(tag);
        }       
        
        private static readonly Asn1Tag ApplicationTag = new Asn1Tag(TagClass.Application, 2);
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() 
        {
          return EncodeApplication(ApplicationTag);
        }
        
        public static KrbAuthenticator DecodeApplication(ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var sequence = reader.ReadSequence(ApplicationTag);
          
            KrbAuthenticator decoded;
            Decode(sequence, Asn1Tag.Sequence, out decoded);
            sequence.ThrowIfNotEmpty();

            reader.ThrowIfNotEmpty();

            return decoded;
        }
        
        internal static KrbAuthenticator DecodeApplication<T>(AsnReader reader, out T decoded)
          where T: KrbAuthenticator, new()
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
        
        internal static KrbAuthenticator Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbAuthenticator decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbAuthenticator Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbAuthenticator decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbAuthenticator, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            DecodeApplication(reader, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbAuthenticator, new()
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

            if (!explicitReader.TryReadInt32(out int tmpAuthenticatorVersionNumber))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.AuthenticatorVersionNumber = tmpAuthenticatorVersionNumber;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpCName);
            decoded.CName = tmpCName;

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));                
            
                KrbChecksum.Decode<KrbChecksum>(explicitReader, out KrbChecksum tmpChecksum);
                decoded.Checksum = tmpChecksum;
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));

            if (!explicitReader.TryReadInt32(out int tmpCuSec))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.CuSec = tmpCuSec;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            decoded.CTime = explicitReader.ReadGeneralizedTime();

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));                
            
                KrbEncryptionKey.Decode<KrbEncryptionKey>(explicitReader, out KrbEncryptionKey tmpSubkey);
                decoded.Subkey = tmpSubkey;
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));                
            
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

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));                
            
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
