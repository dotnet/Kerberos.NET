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
    public partial class KrbFastReq
    {
        /*
          KrbFastReq ::= SEQUENCE {
              fast-options [0] FastOptions,
                  - - Additional options.
              padata       [1] SEQUENCE OF PA-DATA,
                  - - padata typed holes.
              req-body     [2] KDC-REQ-BODY,
                  - - Contains the KDC request body as defined in Section
                  - - 5.4.1 of [RFC4120].
                  - - This req-body field is preferred over the outer field
                  - - in the KDC request.
               ...
          }
         */
    
        public FastOptions FastOptions { get; set; }
        public KrbPaData[] PaData { get; set; }
  
        public KrbKdcReqBody ReqBody { get; set; }
  
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
            writer.WriteBitString(FastOptions.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence();
            
            for (int i = 0; i < PaData.Length; i++)
            {
                PaData[i]?.Encode(writer); 
            }

            writer.PopSequence();

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            ReqBody?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
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
        
        public static KrbFastReq Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbFastReq Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }
        
        internal static KrbFastReq Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbFastReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbFastReq Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbFastReq decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbFastReq, new()
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbFastReq, new()
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

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpFastOptions))
            {
                decoded.FastOptions = (FastOptions)tmpFastOptions.AsLong();
            }
            else
            {
                decoded.FastOptions = (FastOptions)explicitReader.ReadBitString(out _).AsLong();
            }


            explicitReader.ThrowIfNotEmpty();

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
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

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            KrbKdcReqBody.Decode<KrbKdcReqBody>(explicitReader, out KrbKdcReqBody tmpReqBody);
            decoded.ReqBody = tmpReqBody;

            explicitReader.ThrowIfNotEmpty();

            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
