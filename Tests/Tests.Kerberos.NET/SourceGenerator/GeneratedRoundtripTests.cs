using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET.SourceGenerator
{
    /// <summary>
    /// Verifies encode/decode roundtrip correctness for each source generator code pattern.
    /// These tests construct objects from scratch (not from fixture data) so they validate
    /// the generated Encode/Decode methods independently of the existing test data.
    /// </summary>
    [TestClass]
    public class GeneratedRoundtripTests
    {
        // ────────────────────────────────────────────────────────
        // Pattern 1: SEQUENCE + APPLICATION tag
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void KrbTicket_RoundTrip()
        {
            var original = new KrbTicket
            {
                TicketNumber = 5,
                Realm = "EXAMPLE.COM",
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { "krbtgt", "EXAMPLE.COM" }
                },
                EncryptedPart = new KrbEncryptedData
                {
                    EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    Cipher = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }
                }
            };

            var encoded = original.EncodeApplication();
            var decoded = KrbTicket.DecodeApplication(encoded);

            Assert.AreEqual(original.TicketNumber, decoded.TicketNumber);
            Assert.AreEqual(original.Realm, decoded.Realm);
            Assert.AreEqual(original.SName.Type, decoded.SName.Type);
            Assert.IsTrue(original.SName.Name.SequenceEqual(decoded.SName.Name));
            Assert.AreEqual(original.EncryptedPart.EType, decoded.EncryptedPart.EType);
            Assert.IsTrue(original.EncryptedPart.Cipher.Span.SequenceEqual(decoded.EncryptedPart.Cipher.Span));
        }

        [TestMethod]
        public void KrbError_RoundTrip()
        {
            var original = new KrbError
            {
                ProtocolVersionNumber = 5,
                MessageType = MessageType.KRB_ERROR,
                STime = DateTimeOffset.UtcNow,
                Susc = 123456,
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                Realm = "EXAMPLE.COM",
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { "krbtgt", "EXAMPLE.COM" }
                },
                EText = "Pre-authentication required",
                EData = new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 }
            };

            var encoded = original.EncodeApplication();
            var decoded = KrbError.DecodeApplication(encoded);

            Assert.AreEqual(original.ErrorCode, decoded.ErrorCode);
            Assert.AreEqual(original.Realm, decoded.Realm);
            Assert.AreEqual(original.EText, decoded.EText);
            Assert.IsTrue(original.EData.Value.Span.SequenceEqual(decoded.EData.Value.Span));
        }

        // ────────────────────────────────────────────────────────
        // Pattern 2: SEQUENCE without APPLICATION tag
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void KrbPaData_RoundTrip()
        {
            var original = new KrbPaData
            {
                Type = PaDataType.PA_ENC_TIMESTAMP,
                Value = new byte[] { 0x30, 0x0D, 0x06, 0x09 }
            };

            var encoded = original.Encode();
            var decoded = KrbPaData.Decode(encoded);

            Assert.AreEqual(original.Type, decoded.Type);
            Assert.IsTrue(original.Value.Span.SequenceEqual(decoded.Value.Span));
        }

        [TestMethod]
        public void KrbEncryptionKey_RoundTrip()
        {
            var original = new KrbEncryptionKey
            {
                EType = EncryptionType.AES128_CTS_HMAC_SHA1_96,
                KeyValue = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }
            };

            var encoded = original.Encode();
            var decoded = KrbEncryptionKey.Decode(encoded);

            Assert.AreEqual(original.EType, decoded.EType);
            Assert.IsTrue(original.KeyValue.Span.SequenceEqual(decoded.KeyValue.Span));
        }

        [TestMethod]
        public void KrbChecksum_RoundTrip()
        {
            var original = new KrbChecksum
            {
                Type = ChecksumType.HMAC_SHA1_96_AES128,
                Checksum = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }
            };

            var encoded = original.Encode();
            var decoded = KrbChecksum.Decode(encoded);

            Assert.AreEqual(original.Type, decoded.Type);
            Assert.IsTrue(original.Checksum.Span.SequenceEqual(decoded.Checksum.Span));
        }

        // ────────────────────────────────────────────────────────
        // Pattern 3: InheritedSequence (derived APPLICATION tag)
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void KrbAsReq_InheritedRoundTrip()
        {
            var original = new KrbAsReq
            {
                MessageType = MessageType.KRB_AS_REQ,
                PaData = new[]
                {
                    new KrbPaData
                    {
                        Type = PaDataType.PA_ENC_TIMESTAMP,
                        Value = new byte[] { 1, 2, 3 }
                    }
                },
                Body = new KrbKdcReqBody
                {
                    EType = new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96 },
                    Nonce = 12345,
                    Realm = "EXAMPLE.COM",
                    CName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_PRINCIPAL,
                        Name = new[] { "testuser" }
                    },
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", "EXAMPLE.COM" }
                    },
                    Till = DateTimeOffset.UtcNow.AddHours(8),
                    KdcOptions = KdcOptions.Forwardable | KdcOptions.Renewable
                }
            };

            var encoded = original.EncodeApplication();
            var decoded = KrbAsReq.DecodeApplication(encoded);

            Assert.AreEqual(original.Body.Nonce, decoded.Body.Nonce);
            Assert.AreEqual(original.Body.Realm, decoded.Body.Realm);
            Assert.AreEqual(original.PaData.Length, decoded.PaData.Length);
            Assert.AreEqual(original.PaData[0].Type, decoded.PaData[0].Type);
        }

        [TestMethod]
        public void KrbTgsReq_InheritedRoundTrip()
        {
            var original = new KrbTgsReq
            {
                MessageType = MessageType.KRB_TGS_REQ,
                Body = new KrbKdcReqBody
                {
                    EType = new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96 },
                    Nonce = 99999,
                    Realm = "OTHER.COM",
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "http", "server.other.com" }
                    },
                    Till = DateTimeOffset.UtcNow.AddHours(4),
                    KdcOptions = KdcOptions.Renewable
                }
            };

            var encoded = original.EncodeApplication();
            var decoded = KrbTgsReq.DecodeApplication(encoded);

            Assert.AreEqual(original.Body.Nonce, decoded.Body.Nonce);
            Assert.AreEqual(original.Body.Realm, decoded.Body.Realm);
        }

        // ────────────────────────────────────────────────────────
        // Pattern 4: CollectionWrapper
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void KrbMethodData_CollectionWrapper_RoundTrip()
        {
            var original = new KrbMethodData
            {
                MethodData = new[]
                {
                    new KrbPaData { Type = PaDataType.PA_ENC_TIMESTAMP, Value = new byte[] { 1 } },
                    new KrbPaData { Type = PaDataType.PA_ETYPE_INFO2, Value = new byte[] { 2, 3 } },
                }
            };

            var encoded = original.Encode();
            var decoded = KrbMethodData.Decode(encoded);

            Assert.AreEqual(2, decoded.MethodData.Length);
            Assert.AreEqual(PaDataType.PA_ENC_TIMESTAMP, decoded.MethodData[0].Type);
            Assert.AreEqual(PaDataType.PA_ETYPE_INFO2, decoded.MethodData[1].Type);
        }

        [TestMethod]
        public void KrbETypeInfo2_CollectionWrapper_RoundTrip()
        {
            var original = new KrbETypeInfo2
            {
                ETypeInfo = new[]
                {
                    new KrbETypeInfo2Entry
                    {
                        EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                        Salt = "EXAMPLE.COMtestuser"
                    },
                    new KrbETypeInfo2Entry
                    {
                        EType = EncryptionType.AES128_CTS_HMAC_SHA1_96,
                        Salt = "EXAMPLE.COMtestuser"
                    },
                }
            };

            var encoded = original.Encode();
            var decoded = KrbETypeInfo2.Decode(encoded);

            Assert.AreEqual(2, decoded.ETypeInfo.Length);
            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, decoded.ETypeInfo[0].EType);
            Assert.AreEqual("EXAMPLE.COMtestuser", decoded.ETypeInfo[0].Salt);
        }

        [TestMethod]
        public void KrbETypeList_CollectionWrapper_RoundTrip()
        {
            var original = new KrbETypeList
            {
                List = new[]
                {
                    EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    EncryptionType.AES128_CTS_HMAC_SHA1_96,
                    EncryptionType.RC4_HMAC_NT
                }
            };

            var encoded = original.Encode();
            var decoded = KrbETypeList.Decode(encoded);

            Assert.AreEqual(3, decoded.List.Length);
            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, decoded.List[0]);
            Assert.AreEqual(EncryptionType.RC4_HMAC_NT, decoded.List[2]);
        }

        [TestMethod]
        public void KrbAuthorizationDataSequence_CollectionWrapper_RoundTrip()
        {
            var original = new KrbAuthorizationDataSequence
            {
                AuthorizationData = new[]
                {
                    new KrbAuthorizationData
                    {
                        Type = AuthorizationDataType.AdIfRelevant,
                        Data = new byte[] { 0x30, 0x00 }
                    }
                }
            };

            var encoded = original.Encode();
            var decoded = KrbAuthorizationDataSequence.Decode(encoded);

            Assert.AreEqual(1, decoded.AuthorizationData.Length);
            Assert.AreEqual(AuthorizationDataType.AdIfRelevant, decoded.AuthorizationData[0].Type);
        }

        // ────────────────────────────────────────────────────────
        // Pattern 5: CHOICE
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void NegotiationToken_Choice_InitToken_RoundTrip()
        {
            var original = new NegotiationToken
            {
                InitialToken = new NegTokenInit
                {
                    MechTypes = new Oid[] { new Oid("1.2.840.113554.1.2.2") },
                    MechToken = new byte[] { 1, 2, 3, 4, 5 }
                }
            };

            var encoded = original.Encode();
            var decoded = NegotiationToken.Decode(encoded);

            Assert.IsNotNull(decoded.InitialToken);
            Assert.AreEqual(1, decoded.InitialToken.MechTypes.Length);
            Assert.IsTrue(original.InitialToken.MechToken.Value.Span.SequenceEqual(decoded.InitialToken.MechToken.Value.Span));
        }

        // ────────────────────────────────────────────────────────
        // Optional field omission
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void OptionalFieldsOmitted_WhenNull()
        {
            var original = new KrbEncTicketPart
            {
                Flags = TicketFlags.Forwardable,
                Key = new KrbEncryptionKey
                {
                    EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    KeyValue = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }
                },
                CRealm = "EXAMPLE.COM",
                CName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { "user" }
                },
                Transited = new KrbTransitedEncoding
                {
                    Type = 0,
                    Contents = Array.Empty<byte>()
                },
                AuthTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow.AddHours(8),
                // StartTime, RenewTill, CAddr, AuthorizationData all null/default
            };

            var encoded = original.EncodeApplication();
            var decoded = KrbEncTicketPart.DecodeApplication(encoded);

            Assert.AreEqual("EXAMPLE.COM", decoded.CRealm);
            Assert.IsNull(decoded.StartTime);
            Assert.IsNull(decoded.RenewTill);
            Assert.IsNull(decoded.CAddr);
            Assert.IsNull(decoded.AuthorizationData);
        }

        [TestMethod]
        public void OptionalFlagsEnum_DefaultValueWhenNotPresent()
        {
            var original = new KrbCredInfo
            {
                Key = new KrbEncryptionKey
                {
                    EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    KeyValue = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }
                },
                // Flags is OPTIONAL but not nullable (flags enum default = 0)
            };

            var encoded = original.Encode();
            var decoded = KrbCredInfo.Decode(encoded);

            Assert.IsNull(decoded.Flags, "Optional flags enum field should be null when not present");
        }

        // ────────────────────────────────────────────────────────
        // ENUMERATED with @cs-enum
        // ────────────────────────────────────────────────────────

        [TestMethod]
        public void NegTokenResp_EnumeratedField_RoundTrip()
        {
            var original = new NegTokenResp
            {
                State = NegotiateState.Rejected,
                SupportedMech = new Oid("1.2.840.113554.1.2.2"),
                ResponseToken = new byte[] { 0xFF }
            };

            var encoded = original.Encode();
            var decoded = NegTokenResp.Decode(encoded);

            Assert.AreEqual(NegotiateState.Rejected, decoded.State);
        }

        [TestMethod]
        public void NegTokenResp_NullState_StillEncodes()
        {
            var original = new NegTokenResp
            {
                SupportedMech = new Oid("1.2.840.113554.1.2.2"),
                ResponseToken = new byte[] { 0xAA },
                // State not set (null)
            };

            var encoded = original.Encode();
            var decoded = NegTokenResp.Decode(encoded);

            Assert.IsNull(decoded.State);
            Assert.IsNotNull(decoded.SupportedMech);
        }
    }
}
