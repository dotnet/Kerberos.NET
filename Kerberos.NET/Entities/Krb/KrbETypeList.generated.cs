// This is a generated file.
// This file is licensed as per the LICENSE file.
// The generation template has been modified from .NET Foundation implementation
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbETypeList
    {
        public EncryptionType[] List;

#if DEBUG
        static KrbETypeList()
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
            
            ensureUniqueTag(Asn1Tag.Sequence, "List");
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
            
            if (List != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                

                writer.PushSequence();
                for (int i = 0; i < List.Length; i++)
                {
                    writer.WriteInteger((long)List[i]); 
                }
                writer.PopSequence();

                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }
                
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence(tag);
                
                this.Encode(writer);

                writer.PopSequence(tag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }
        
        public static KrbETypeList Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbETypeList Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbETypeList decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbETypeList, new()
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new T();
            Asn1Tag tag = reader.PeekTag();
            AsnReader collectionReader;
            
            if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {

                // Decode SEQUENCE OF for List
                {
                    collectionReader = reader.ReadSequence();
                    var tmpList = new List<EncryptionType>();
                    EncryptionType tmpItem;

                    while (collectionReader.HasData)
                    {

                        if (!collectionReader.TryReadInt32(out tmpItem))
                        {
                            collectionReader.ThrowIfNotEmpty();
                        }
 
                        tmpList.Add(tmpItem);
                    }

                    decoded.List = tmpList.ToArray();
                }

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
