
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbAsReq : IAsn1Encoder
    {
        public KrbKdcReq AsReq;

#if DEBUG
        static KrbAsReq()
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
            
            ensureUniqueTag(Asn1Tag.Sequence, "AsReq");
        }
#endif
        public ReadOnlySpan<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsSpan();
        }

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (HasValue(AsReq))
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                AsReq?.Encode(writer);
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }
        
        object IAsn1Encoder.Decode(ReadOnlyMemory<byte> data) 
        {
            return Decode(data);
        }
        
        public static KrbAsReq Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbAsReq Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbAsReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbAsReq decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbAsReq();
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                KrbKdcReq tmpAsReq;
                KrbKdcReq.Decode(reader, out tmpAsReq);
                decoded.AsReq = tmpAsReq;

            }
            else
            {
                throw new CryptographicException();
            }
        }
        
        private static bool HasValue(object thing) 
        {
            return thing != null;
        }
    }
}
