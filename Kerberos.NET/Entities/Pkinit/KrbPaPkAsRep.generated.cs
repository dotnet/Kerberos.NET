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
    public partial class KrbPaPkAsRep
    {
        /*
          PA-PK-AS-REP ::= CHOICE {
            dhInfo                  [0] DHRepInfo,
          		   - - Selected when Diffie-Hellman key exchange is
          		   - - used.
            encKeyPack              [1] IMPLICIT OCTET STRING,
          		   - - Selected when public key encryption is used.
          		   - - Contains a CMS type ContentInfo encoded
          		   - - according to [RFC3852].
          		   - - The contentType field of the type ContentInfo is
          		   - - id-envelopedData (1.2.840.113549.1.7.3).
          		   - - The content field is an EnvelopedData.
          		   - - The contentType field for the type EnvelopedData
          		   - - is id-signedData (1.2.840.113549.1.7.2).
          		   - - The eContentType field for the inner type
          		   - - SignedData (when unencrypted) is
          		   - - id-pkinit-rkeyData (1.3.6.1.5.2.3.3) and the
          		   - - eContent field contains the DER encoding of the
          		   - - type ReplyKeyPack.
          		   - - ReplyKeyPack is defined below.
            ...
          }
         */
    
        public KrbDHReplyInfo DHInfo { get; set; }
  
        public ReadOnlyMemory<byte>? EncKeyPack { get; set; }
  
#if DEBUG
        static KrbPaPkAsRep()
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
            
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 0), "DHInfo");
            ensureUniqueTag(new Asn1Tag(TagClass.ContextSpecific, 1), "EncKeyPack");
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
            
            if (Asn1Extension.HasValue(DHInfo))
            {
                if (wroteValue)
                {
                    throw new CryptographicException();
                }
                
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                DHInfo?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                wroteValue = true;
            }
            if (Asn1Extension.HasValue(EncKeyPack))
            {
                if (wroteValue)
                {
                    throw new CryptographicException();
                }
                
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteOctetString(EncKeyPack.Value.Span);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
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
        
        public static KrbPaPkAsRep Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbPaPkAsRep Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, out KrbPaPkAsRep decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbPaPkAsRep, new()
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
                KrbDHReplyInfo.Decode<KrbDHReplyInfo>(explicitReader, out KrbDHReplyInfo tmpDHInfo);
                decoded.DHInfo = tmpDHInfo;
                explicitReader.ThrowIfNotEmpty();
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

                if (explicitReader.TryReadPrimitiveOctetStringBytes(out ReadOnlyMemory<byte> tmpEncKeyPack))
                {
                    decoded.EncKeyPack = tmpEncKeyPack;
                }
                else
                {
                    decoded.EncKeyPack = explicitReader.ReadOctetString();
                }
                explicitReader.ThrowIfNotEmpty();
            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}
