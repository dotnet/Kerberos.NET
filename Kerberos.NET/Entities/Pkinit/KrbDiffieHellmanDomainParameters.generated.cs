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
    public partial class KrbDiffieHellmanDomainParameters
    {
        public ReadOnlyMemory<byte> P { get; set; }
  
        public ReadOnlyMemory<byte> G { get; set; }
  
        public ReadOnlyMemory<byte> Q { get; set; }
  
        public ReadOnlyMemory<byte>? J { get; set; }
  
        public KrbDiffieHellmanValidationParameters ValidationParameters { get; set; }
  
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
            
            writer.WriteEncodedValue(P.Span);
            writer.WriteEncodedValue(G.Span);
            writer.WriteEncodedValue(Q.Span);

            if (Asn1Extension.HasValue(J))
            {
                writer.WriteEncodedValue(J.Value.Span);
            }

            if (Asn1Extension.HasValue(ValidationParameters))
            {
                ValidationParameters?.Encode(writer);
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
        
        public static KrbDiffieHellmanDomainParameters Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbDiffieHellmanDomainParameters Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbDiffieHellmanDomainParameters Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbDiffieHellmanDomainParameters decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbDiffieHellmanDomainParameters Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbDiffieHellmanDomainParameters decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbDiffieHellmanDomainParameters, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbDiffieHellmanDomainParameters, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            
            decoded.P = sequenceReader.ReadEncodedValue();
            decoded.G = sequenceReader.ReadEncodedValue();
            decoded.Q = sequenceReader.ReadEncodedValue();

            if (sequenceReader.HasData)
            {
                decoded.J = sequenceReader.ReadEncodedValue();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                KrbDiffieHellmanValidationParameters.Decode<KrbDiffieHellmanValidationParameters>(sequenceReader, out KrbDiffieHellmanValidationParameters tmpValidationParameters);
                decoded.ValidationParameters = tmpValidationParameters;
            }

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
