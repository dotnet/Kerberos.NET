
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public partial struct KrbApChoice
    {
        public KrbApReq? ApReq;
        public KrbApRep? ApRep;

#if DEBUG
        static KrbApChoice()
        {
            var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();
            Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>
            {
                if (usedTags.TryGetValue(tag, out string existing))
                {
                    throw new InvalidOperationException($"Tag '{tag}' is in use by both '{existing}' and '{fieldName}'");
                }

                usedTags.Add(tag, fieldName);
            };
            
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 14), "ApReq");
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 15), "ApRep");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (ApReq.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.PushSequence(new Asn1Tag(TagClass.Application, 14));
                ApReq.Value.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.Application, 14));
                wroteValue = true;
            }

            if (ApRep.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.PushSequence(new Asn1Tag(TagClass.Application, 15));
                ApRep.Value.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.Application, 15));
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }
        
        public static KrbApChoice Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbApChoice Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbApChoice decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbApChoice decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            Asn1Tag tag = reader.PeekTag();
            AsnReader explicitReader;
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 14)))
            {
                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.Application, 14));
                KrbApReq tmpApReq;
                KrbApReq.Decode(explicitReader, out tmpApReq);
                decoded.ApReq = tmpApReq;

                explicitReader.ThrowIfNotEmpty();
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 15)))
            {
                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.Application, 15));
                KrbApRep tmpApRep;
                KrbApRep.Decode(explicitReader, out tmpApRep);
                decoded.ApRep = tmpApRep;

                explicitReader.ThrowIfNotEmpty();
            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}
