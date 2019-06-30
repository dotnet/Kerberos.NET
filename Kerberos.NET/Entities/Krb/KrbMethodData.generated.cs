
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public partial struct KrbMethodData
    {
        public KrbPaData[] MethodData;

#if DEBUG
        static KrbMethodData()
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
            
            ensureUniqueTag(Asn1Tag.Sequence, "MethodData");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (MethodData != null)
            {
                if (wroteValue)
                    throw new CryptographicException();
                

                writer.PushSequence();
                for (int i = 0; i < MethodData.Length; i++)
                {
                    MethodData[i].Encode(writer); 
                }
                writer.PopSequence();

                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }
        
        public static KrbMethodData Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbMethodData Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbMethodData decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbMethodData decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            Asn1Tag tag = reader.PeekTag();
            AsnReader collectionReader;
            
            if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {

                // Decode SEQUENCE OF for MethodData
                {
                    collectionReader = reader.ReadSequence();
                    var tmpList = new List<KrbPaData>();
                    KrbPaData tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbPaData.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.MethodData = tmpList.ToArray();
                }

            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}
