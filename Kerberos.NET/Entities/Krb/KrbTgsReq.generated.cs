
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbTgsReq : IAsn1Encoder
    {
        public KrbKdcReq TgsReq;

#if DEBUG
        static KrbTgsReq()
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
            
            ensureUniqueTag(Asn1Tag.Sequence, "TgsReq");
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
            
            if (HasValue(TgsReq))
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                TgsReq?.Encode(writer);
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
        
        public static KrbTgsReq Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbTgsReq Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbTgsReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbTgsReq decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbTgsReq();
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                KrbKdcReq tmpTgsReq;
                KrbKdcReq.Decode(reader, out tmpTgsReq);
                decoded.TgsReq = tmpTgsReq;

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
