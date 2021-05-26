// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

// This is a generated file.
// The generation template has been modified from .NET Runtime implementation

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbPaFxFastReply
    {
        /*
          PA-FX-FAST-REPLY ::= CHOICE {
              armored-data [0] KrbFastArmoredRep,
              ...
          }
         */
    
        public KrbFastArmoredRep ArmoredData { get; set; }
  
#if DEBUG
        static KrbPaFxFastReply()
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
            
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 0), "ArmoredData");
        }
#endif
        // Encoding methods
        public ReadOnlyMemory<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsMemory();
        }

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (Asn1Extension.HasValue(ArmoredData))
            {
                if (wroteValue)
                {
                    throw new CryptographicException();
                }
                
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                ArmoredData?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
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

                return writer.EncodeAsMemory();
            }
        }
        
        public static KrbPaFxFastReply Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbPaFxFastReply Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbPaFxFastReply decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbPaFxFastReply, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            Asn1Tag tag = reader.PeekTag();
            AsnReader explicitReader;
            
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                KrbFastArmoredRep.Decode<KrbFastArmoredRep>(explicitReader, out KrbFastArmoredRep tmpArmoredData);
                decoded.ArmoredData = tmpArmoredData;
                explicitReader.ThrowIfNotEmpty();
            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}
