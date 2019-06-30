
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Asn1.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public partial struct KrbCredInfo
    {
        public KrbEncryptionKey Key;
        public string Realm;
        public KrbPrincipalName? PName;
        public TicketFlags Flags;
    
        public DateTimeOffset? AuthTime;
        public DateTimeOffset? StartTime;
        public DateTimeOffset? EndTime;
        public DateTimeOffset? RenewTill;
        public string SRealm;
        public KrbPrincipalName? SName;
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
            Key.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (Realm != null)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            }


            if (PName.HasValue)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                PName.Value.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            writer.WriteBitString(Flags.AsReadOnly());
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            if (AuthTime.HasValue)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                writer.WriteGeneralizedTime(AuthTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            }


            if (StartTime.HasValue)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
                writer.WriteGeneralizedTime(StartTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            }


            if (EndTime.HasValue)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                writer.WriteGeneralizedTime(EndTime.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }


            if (RenewTill.HasValue)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                writer.WriteGeneralizedTime(RenewTill.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            }


            if (SRealm != null)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                writer.WriteCharacterString(UniversalTagNumber.GeneralString, SRealm);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }


            if (SName.HasValue)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
                SName.Value.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
            }


            if (AuthorizationData != null)
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 10));

                writer.PushSequence();
                for (int i = 0; i < AuthorizationData.Length; i++)
                {
                    AuthorizationData[i].Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 10));
            }

            writer.PopSequence(tag);
        }
        
        public static KrbCredInfo Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbCredInfo Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbCredInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbCredInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbCredInfo Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbCredInfo decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbCredInfo decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out KrbCredInfo decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            KrbEncryptionKey.Decode(explicitReader, out decoded.Key);
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
                decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                KrbPrincipalName tmpPName;
                KrbPrincipalName.Decode(explicitReader, out tmpPName);
                decoded.PName = tmpPName;

                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));

            if (explicitReader.TryReadPrimitiveBitStringValue(out _, out ReadOnlyMemory<byte> tmpFlags))
            {
                decoded.Flags = (TicketFlags)tmpFlags.AsLong();
            }
            else
            {
                decoded.Flags = (TicketFlags)explicitReader.ReadBitString(out _).AsLong();
            }

            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 4)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
                decoded.AuthTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 5)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
                decoded.StartTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                decoded.EndTime = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                decoded.RenewTill = explicitReader.ReadGeneralizedTime();
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
                decoded.SRealm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 9)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 9));
                KrbPrincipalName tmpSName;
                KrbPrincipalName.Decode(explicitReader, out tmpSName);
                decoded.SName = tmpSName;

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
    }
}
