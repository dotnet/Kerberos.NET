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
    public partial class KrbKdcRep
    {
        public int ProtocolVersionNumber;
        public MessageType MessageType;
        public KrbPaData[] PaData;
        public string CRealm;
        public KrbPrincipalName CName;
        public KrbTicket Ticket;
        public KrbEncryptedData EncPart;
      
        public ReadOnlySpan<byte> Encode()
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);

            Encode(writer);

            return writer.EncodeAsSpan();
        }
        
        internal void Encode(AsnWriter writer)
        {
            
            Encode(writer, Asn1Tag.Sequence);
        }
        
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.WriteInteger(ProtocolVersionNumber);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteInteger((long)MessageType);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (HasValue(PaData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

                writer.PushSequence();
                for (int i = 0; i < PaData.Length; i++)
                {
                    PaData[i]?.Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, CRealm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            CName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            Ticket?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            EncPart?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            writer.PopSequence(tag);
        }
        
        internal void EncodeApplication(AsnWriter writer, Asn1Tag tag)
        {
                writer.PushSequence(tag);
                
                this.Encode(writer, Asn1Tag.Sequence);

                writer.PopSequence(tag);
        }        
         
        internal ReadOnlyMemory<byte> EncodeApplication(Asn1Tag tag)
        {
            using (var writer = new AsnWriter(AsnEncodingRules.DER))
            {
                EncodeApplication(writer, tag);

                var span = writer.EncodeAsSpan();

                return span.AsMemory();
            }
        }
        
        public static KrbKdcRep Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbKdcRep Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbKdcRep Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbKdcRep decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbKdcRep Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbKdcRep decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode<T>(AsnReader reader, out T decoded)
          where T: KrbKdcRep, new()
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));
            
            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode<T>(AsnReader reader, Asn1Tag expectedTag, out T decoded)
          where T: KrbKdcRep, new()
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new T();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (!explicitReader.TryReadInt32(out decoded.ProtocolVersionNumber))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));

            if (!explicitReader.TryReadInt32(out decoded.MessageType))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

                // Decode SEQUENCE OF for PaData
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbPaData>();
                    KrbPaData tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbPaData.Decode<KrbPaData>(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.PaData = tmpList.ToArray();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            decoded.CRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            KrbPrincipalName.Decode<KrbPrincipalName>(explicitReader, out decoded.CName);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            KrbTicket.Decode<KrbTicket>(explicitReader, out decoded.Ticket);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            KrbEncryptedData.Decode<KrbEncryptedData>(explicitReader, out decoded.EncPart);
            explicitReader.ThrowIfNotEmpty();


            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static bool HasValue(object thing) 
        {
            return thing != null;
        }
    }
}
