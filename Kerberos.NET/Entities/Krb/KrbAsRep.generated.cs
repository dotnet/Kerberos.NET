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
    public partial class KrbAsRep
    {
        public KrbKdcRep Response;
      
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
            
            Response?.Encode(writer);
            writer.PopSequence(tag);
        }
        
        public static KrbAsRep Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbAsRep Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbAsRep Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbAsRep decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbAsRep Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbAsRep decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbAsRep decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out KrbAsRep decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbAsRep();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            
            KrbKdcRep.Decode(sequenceReader, out decoded.Response);

            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static bool HasValue(object thing) 
        {
            return thing != null;
        }
    }
}
