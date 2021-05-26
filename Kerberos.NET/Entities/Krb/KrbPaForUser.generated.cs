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
    public partial class KrbPaForUser
    {
        /*
          PA-FOR-USER     ::= SEQUENCE {
              userName        [0] PrincipalName,
              userRealm       [1] Realm,
              cksum           [2] Checksum,
              auth-package    [3] KerberosString
          }
         */
    
        public KrbPrincipalName UserName { get; set; }
  
        public string UserRealm { get; set; }
  
        public KrbChecksum Checksum { get; set; }
  
        public string AuthPackage { get; set; }
  
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
            UserName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, UserRealm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            Checksum?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, AuthPackage);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
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
        
        public static KrbPaForUser Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbPaForUser Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbPaForUser Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbPaForUser decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbPaForUser Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbPaForUser decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbPaForUser, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbPaForUser, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out KrbPrincipalName tmpUserName);
            decoded.UserName = tmpUserName;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            decoded.UserRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            KrbChecksum.Decode<KrbChecksum>(explicitReader, out KrbChecksum tmpChecksum);
            decoded.Checksum = tmpChecksum;

            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            decoded.AuthPackage = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);

            explicitReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
