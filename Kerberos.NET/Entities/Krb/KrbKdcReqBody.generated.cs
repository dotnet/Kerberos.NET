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
    public partial class KrbKdcReqBody
    {
        public KdcOptions KdcOptions;
    
        public KrbPrincipalName CName;
        public string Realm;
        public KrbPrincipalName SName;
        public DateTimeOffset? From;
        public DateTimeOffset Till;
        public DateTimeOffset? RTime;
        public int Nonce;
        public EncryptionType[] EType;
        public KrbHostAddress[] Addresses;
        public KrbEncryptedData EncAuthorizationData;
        public KrbTicket[] AdditionalTickets;
      
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
            writer.WriteBitString(KdcOptions.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (HasValue(CName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                CName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (HasValue(SName))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                SName?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }


            if (HasValue(From))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                writer.WriteGeneralizedTime(From.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteGeneralizedTime(Till);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (HasValue(RTime))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.WriteGeneralizedTime(RTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            writer.WriteInteger(Nonce);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));

            writer.PushSequence();
            for (int i = 0; i < EType.Length; i++)
            {
                writer.WriteInteger((long)EType[i]); 
            }
            writer.PopSequence();

            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));

            if (HasValue(Addresses))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));

                writer.PushSequence();
                for (int i = 0; i < Addresses.Length; i++)
                {
                    Addresses[i]?.Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            }


            if (HasValue(EncAuthorizationData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
                EncAuthorizationData?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            }


            if (HasValue(AdditionalTickets))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 11));

                writer.PushSequence();
                for (int i = 0; i < AdditionalTickets.Length; i++)
                {
                    AdditionalTickets[i]?.Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 11));
            }

            writer.PopSequence(tag);
        }
        
        public static KrbKdcReqBody Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbKdcReqBody Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbKdcReqBody Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbKdcReqBody decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbKdcReqBody Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbKdcReqBody decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbKdcReqBody decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out KrbKdcReqBody decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbKdcReqBody();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpKdcOptions))
            {
                decoded.KdcOptions = (KdcOptions)tmpKdcOptions.AsLong();
            }
            else
            {
                decoded.KdcOptions = (KdcOptions)explicitReader.ReadBitString(out _).AsLong();
            }

            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                KrbPrincipalName tmpCName;
                KrbPrincipalName.Decode(explicitReader, out tmpCName);
                decoded.CName = tmpCName;

                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                KrbPrincipalName tmpSName;
                KrbPrincipalName.Decode(explicitReader, out tmpSName);
                decoded.SName = tmpSName;

                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                decoded.From = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            decoded.Till = explicitReader.ReadGeneralizedTime();
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                decoded.RTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));

            if (!explicitReader.TryReadInt32(out decoded.Nonce))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));

            // Decode SEQUENCE OF for EType
            {
                collectionReader = explicitReader.ReadSequence();
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

                decoded.EType = tmpList.ToArray();
            }

            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));

                // Decode SEQUENCE OF for Addresses
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbHostAddress>();
                    KrbHostAddress tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbHostAddress.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.Addresses = tmpList.ToArray();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 10)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
                KrbEncryptedData tmpEncAuthorizationData;
                KrbEncryptedData.Decode(explicitReader, out tmpEncAuthorizationData);
                decoded.EncAuthorizationData = tmpEncAuthorizationData;

                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 11)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 11));

                // Decode SEQUENCE OF for AdditionalTickets
                {
                    collectionReader = explicitReader.ReadSequence();
                    var tmpList = new List<KrbTicket>();
                    KrbTicket tmpItem;

                    while (collectionReader.HasData)
                    {
                        KrbTicket.Decode(collectionReader, out tmpItem); 
                        tmpList.Add(tmpItem);
                    }

                    decoded.AdditionalTickets = tmpList.ToArray();
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
