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
    public partial class KrbAuthenticator
    {
        public int AuthenticatorVersionNumber;
        public string Realm;
        public KrbPrincipalName CName;
        public KrbChecksum Checksum;
        public int Cusec;
        public DateTimeOffset CTime;
        public KrbEncryptionKey Subkey;
        public int? SequenceNumber;
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
            writer.WriteInteger(AuthenticatorVersionNumber);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.WriteCharacterString(UniversalTagNumber.GeneralString, Realm);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            CName?.Encode(writer);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 2));

            if (HasValue(Checksum))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                Checksum?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            }

            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.WriteInteger(Cusec);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 4));
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            writer.WriteGeneralizedTime(CTime);
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 5));

            if (HasValue(Subkey))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                Subkey?.Encode(writer);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
            }


            if (HasValue(SequenceNumber))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
                writer.WriteInteger(SequenceNumber.Value);
                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 7));
            }


            if (HasValue(AuthorizationData))
            {
                writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8));

                writer.PushSequence();
                for (int i = 0; i < AuthorizationData.Length; i++)
                {
                    AuthorizationData[i]?.Encode(writer); 
                }
                writer.PopSequence();

                writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, 8));
            }

            writer.PopSequence(tag);
        }
        
        public static KrbAuthenticator Decode(ReadOnlyMemory<byte> data)
        {
            return Decode(data, AsnEncodingRules.DER);
        }

        internal static KrbAuthenticator Decode(ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            return Decode(Asn1Tag.Sequence, encoded, ruleSet);
        }

        internal static KrbAuthenticator Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded)
        {
            AsnReader reader = new AsnReader(encoded, AsnEncodingRules.DER);
            
            Decode(reader, expectedTag, out KrbAuthenticator decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static KrbAuthenticator Decode(Asn1Tag expectedTag, ReadOnlyMemory<byte> encoded, AsnEncodingRules ruleSet)
        {
            AsnReader reader = new AsnReader(encoded, ruleSet);
            
            Decode(reader, expectedTag, out KrbAuthenticator decoded);
            reader.ThrowIfNotEmpty();
            return decoded;
        }

        internal static void Decode(AsnReader reader, out KrbAuthenticator decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out KrbAuthenticator decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = new KrbAuthenticator();
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader explicitReader;
            AsnReader collectionReader;
            

            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

            if (!explicitReader.TryReadInt32(out decoded.AuthenticatorVersionNumber))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            decoded.Realm = explicitReader.ReadCharacterString(UniversalTagNumber.GeneralString);
            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            KrbPrincipalName.Decode(explicitReader, out decoded.CName);
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
                KrbChecksum tmpChecksum;
                KrbChecksum.Decode(explicitReader, out tmpChecksum);
                decoded.Checksum = tmpChecksum;

                explicitReader.ThrowIfNotEmpty();
            }


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));

            if (!explicitReader.TryReadInt32(out decoded.Cusec))
            {
                explicitReader.ThrowIfNotEmpty();
            }

            explicitReader.ThrowIfNotEmpty();


            explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 5));
            decoded.CTime = explicitReader.ReadGeneralizedTime();
            explicitReader.ThrowIfNotEmpty();


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 6)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 6));
                KrbEncryptionKey tmpSubkey;
                KrbEncryptionKey.Decode(explicitReader, out tmpSubkey);
                decoded.Subkey = tmpSubkey;

                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 7)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 7));

                if (explicitReader.TryReadInt32(out int tmpSequenceNumber))
                {
                    decoded.SequenceNumber = tmpSequenceNumber;
                }
                else
                {
                    explicitReader.ThrowIfNotEmpty();
                }

                explicitReader.ThrowIfNotEmpty();
            }


            if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 8)))
            {
                explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 8));

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
