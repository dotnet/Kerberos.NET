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
    public partial class KrbS4uUserId
    {
        public int Nonce { get; set; }
  
        public KrbPrincipalName CName { get; set; }
  
        public string Realm { get; set; }
  
        public ReadOnlyMemory<byte>? SubjectCertificate { get; set; }
  
        public S4uOptions Options { get; set; }
    
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
            writer.WriteInteger(Nonce);
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

            if (Asn1Extension.HasValue(SubjectCertificate))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                writer.WriteOctetString(SubjectCertificate.Value.Span);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.WriteBitString(Options.AsReadOnly());
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
        
        public static KrbS4uUserId Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbS4uUserId Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbS4uUserId Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbS4uUserId decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbS4uUserId Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbS4uUserId decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbS4uUserId, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbS4uUserId, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (!explicitReader.TryReadInt32(out int tmpNonce))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.Nonce = tmpNonce;

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
            

                if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpSubjectCertificate))
                {
                    decoded.SubjectCertificate = tmpSubjectCertificate;
                }
                else
                {
                    decoded.SubjectCertificate = explicitReader.ReadOctetString();
                }
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpOptions))
            {
                decoded.Options = (S4uOptions)tmpOptions.AsLong();
            }
            else
            {
                decoded.Options = (S4uOptions)explicitReader.ReadBitString(out _).AsLong();
            }


            explicitReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
