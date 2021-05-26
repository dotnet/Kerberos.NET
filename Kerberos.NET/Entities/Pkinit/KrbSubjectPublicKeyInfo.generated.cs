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
    public partial class KrbSubjectPublicKeyInfo
    {
        /*
          SubjectPublicKeyInfo ::= SEQUENCE {
              algorithm            AlgorithmIdentifier,
              subjectPublicKey     BIT STRING
          }
         */
    
        public KrbAlgorithmIdentifier Algorithm { get; set; }
  
        public ReadOnlyMemory<byte> SubjectPublicKey { get; set; }
    
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
            
            Algorithm?.Encode(writer);
            writer.WriteBitString(SubjectPublicKey.Span);
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
        
        public static KrbSubjectPublicKeyInfo Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbSubjectPublicKeyInfo Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbSubjectPublicKeyInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbSubjectPublicKeyInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbSubjectPublicKeyInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbSubjectPublicKeyInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbSubjectPublicKeyInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbSubjectPublicKeyInfo, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            
            KrbAlgorithmIdentifier.Decode<KrbAlgorithmIdentifier>(sequenceReader, out KrbAlgorithmIdentifier tmpAlgorithm);
            decoded.Algorithm = tmpAlgorithm;

            if (sequenceReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpSubjectPublicKey))
            {
                decoded.SubjectPublicKey = tmpSubjectPublicKey;
            }
            else
            {
                decoded.SubjectPublicKey = sequenceReader.ReadBitString(out _);
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
