
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public partial struct KrbCredApplication
    {
        public KrbCred? Application;

#if DEBUG
        static KrbCredApplication()
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
            
            ensureUniqueTag(new Asn1Tag(TagClass.Application, 22), "Application");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (Application.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.PushSequence(new Asn1Tag(TagClass.Application, 22));
                Application.Value.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.Application, 22));
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }
        
        public static KrbCredApplication Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbCredApplication Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbCredApplication decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbCredApplication decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            Asn1Tag tag = reader.PeekTag();
            AsnReader explicitReader;
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Application, 22)))
            {
                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.Application, 22));
                KrbCred tmpApplication;
                KrbCred.Decode(explicitReader, out tmpApplication);
                decoded.Application = tmpApplication;

                explicitReader.ThrowIfNotEmpty();
            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}
