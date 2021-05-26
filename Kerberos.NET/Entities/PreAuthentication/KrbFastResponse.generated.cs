// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

// This is a generated file.
// The generation template has been modified from .NET Runtime implementation

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbFastResponse
    {
        /*
        KrbFastResponse ::= SEQUENCE {
            padata         [0] SEQUENCE OF PA-DATA,
                - - padata typed holes.
            strengthen-key [1] EncryptionKey OPTIONAL,
                - - This, if present, strengthens the reply key for AS and
                - - TGS. MUST be present for TGS.
                - - MUST be absent in KRB-ERROR.
            finished       [2] KrbFastFinished OPTIONAL,
                - - Present in AS or TGS reply; absent otherwise.
            nonce          [3] UInt32,
                - - Nonce from the client request.
            ...
        }
         */
    
        public KrbPaData[] PaData { get; set; }
  
        public KrbEncryptionKey StrengthenKey { get; set; }
  
        public KrbFastFinished Finished { get; set; }
  
        public int Nonce { get; set; }
  
        // Encoding methods
        public ReadOnlyMemory<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsMemory();
        }
 
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence();
            
            for (int i = 0; i < PaData.Length; i++)
            {
                PaData[i]?.Encode(writer); 
            }

            writer.PopSequence();

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (Asn1Extension.HasValue(StrengthenKey))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                StrengthenKey?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }

            if (Asn1Extension.HasValue(Finished))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                Finished?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.WriteInteger(Nonce);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            this.Encode(writer, Asn1Tag.Sequence);
            
            writer.PopSequence(tag);
        }       
        
        public virtual ReadOnlyMemory<byte> EncodeApplication() => new ReadOnlyMemory<byte>();
         
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                EncodeApplication(writer, tag);

                return writer.EncodeAsMemory();
            }
        }
        
        public static KrbFastResponse Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbFastResponse Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbFastResponse Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbFastResponse decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbFastResponse Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbFastResponse decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbFastResponse, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbFastResponse, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            decoded = new T();
            
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            
            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            // Decode SEQUENCE OF for PaData
            {
                collectionReader = explicitReader.ReadSequence();
                var tmpList = new List<KrbPaData>();
                KrbPaData tmpItem;

                while (collectionReader.HasData)
                {
                    KrbPaData.Decode<KrbPaData>(collectionReader, out KrbPaData tmp);
                    tmpItem = tmp; 
                    tmpList.Add(tmpItem);
                }

                decoded.PaData = tmpList.ToArray();
            }

            explicitReader.ThrowIfNotEmpty();

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));                
            
                KrbEncryptionKey.Decode<KrbEncryptionKey>(explicitReader, out KrbEncryptionKey tmpStrengthenKey);
                decoded.StrengthenKey = tmpStrengthenKey;
                explicitReader.ThrowIfNotEmpty();
            }

            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));                
            
                KrbFastFinished.Decode<KrbFastFinished>(explicitReader, out KrbFastFinished tmpFinished);
                decoded.Finished = tmpFinished;
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            if (!explicitReader.TryReadInt32(out int tmpNonce))
            {
                explicitReader.ThrowIfNotEmpty();
            }
            
            decoded.Nonce = tmpNonce;

            explicitReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
