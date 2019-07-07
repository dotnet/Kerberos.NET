
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KrbEncTicketPart : IAsn1Encoder
    {
        public TicketFlags Flags;
    
        public KrbEncryptionKey Key;
        public string CRealm;
        public KrbPrincipalName CName;
        public KrbTransitedEncoding Transited;
        public DateTimeOffset AuthTime;
        public DateTimeOffset? StartTime;
        public DateTimeOffset EndTime;
        public DateTimeOffset? RenewTill;
        public KrbHostAddress[] CAddr;
        public KrbAuthorizationData[] AuthorizationData;
      
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
            writer.WriteBitString(Flags.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            Key?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, CRealm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            CName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            Transited?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteGeneralizedTime(AuthTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (HasValue(StartTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.WriteGeneralizedTime(StartTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            writer.WriteGeneralizedTime(EndTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));

            if (HasValue(RenewTill))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                writer.WriteGeneralizedTime(RenewTill.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }


            if (HasValue(CAddr))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));

                writer.PushSequence();
                for (int i = 0; i < CAddr.Length; i++)
                {
                    CAddr[i]?.Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            }


            if (HasValue(AuthorizationData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));

                writer.PushSequence();
                for (int i = 0; i < AuthorizationData.Length; i++)
                {
                    AuthorizationData[i]?.Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            }

            writer.PopSequence(tag);
        }
        
        public static KrbEncTicketPart Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbEncTicketPart Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbEncTicketPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbEncTicketPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }
        
        object IAsn1Encoder.Decode(ReadOnlyMemory<byte> data) 
        {
            return Decode(data);
        }

        internal static KrbEncTicketPart Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbEncTicketPart decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbEncTicketPart decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out KrbEncTicketPart decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbEncTicketPart();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpFlags))
            {
                decoded.Flags = (TicketFlags)tmpFlags.AsLong();
            }
            else
            {
                decoded.Flags = (TicketFlags)explicitReader.ReadBitString(out _).AsLong();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            KrbEncryptionKey.Decode(explicitReader, out decoded.Key);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            decoded.CRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            KrbPrincipalName.Decode(explicitReader, out decoded.CName);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            KrbTransitedEncoding.Decode(explicitReader, out decoded.Transited);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            decoded.AuthTime = explicitReader.ReadGeneralizedTime();
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                decoded.StartTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            decoded.EndTime = explicitReader.ReadGeneralizedTime();
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                decoded.RenewTill = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));

                // Decode SEQUENCE OF for CAddr
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbHostAddress>();
                    KrbHostAddress tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbHostAddress.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.CAddr = tmpList.ToArray();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 10));

                // Decode SEQUENCE OF for AuthorizationData
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbAuthorizationData>();
                    KrbAuthorizationData tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbAuthorizationData.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.AuthorizationData = tmpList.ToArray();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static bool HasValue(object thing) 
        {
            return thing != null;
        }
    }
}
