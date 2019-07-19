// This is a generated file.
// This file is licensed as per the LICENSE file.
// The generation template has been modified from .NET Foundation implementation

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class GssApiToken
    {
        public Oid ThisMech;
        public ReadOnlyMemory<byte>? Field1;
        public ReadOnlyMemory<byte>? Field2;
      
        public ReadOnlySpan<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsSpan();
        }
        
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteObjectIdentifier(ThisMech);

            if (HasValue(Field1))
            {
                writer.WriteEncodedValue(Field1.Value.Span);
            }


            if (HasValue(Field2))
            {
                writer.WriteEncodedValue(Field2.Value.Span);
            }

            writer.PopSequence(tag);
        }
        
        public static GssApiToken Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static GssApiToken Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static GssApiToken Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out GssApiToken decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static GssApiToken Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out GssApiToken decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out GssApiToken decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out GssApiToken decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new GssApiToken();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            
            decoded.ThisMech = sequenceReader.ReadObjectIdentifier();

            if (sequenceReader.HasData)
            {
                decoded.Field1 = sequenceReader.ReadEncodedValue();
            }


            if (sequenceReader.HasData)
            {
                decoded.Field2 = sequenceReader.ReadEncodedValue();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static bool HasValue(object thing) 
        {
            return thing != null;
        }
    }
}
