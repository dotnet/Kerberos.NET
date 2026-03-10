// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Security.Cryptography;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ChannelBindingTests : BaseTest
    {
        private static readonly byte[] SampleTlsBinding = new byte[]
        {
            0x74, 0x6C, 0x73, 0x2D, 0x73, 0x65, 0x72, 0x76,
            0x65, 0x72, 0x2D, 0x65, 0x6E, 0x64, 0x2D, 0x70,
            0x6F, 0x69, 0x6E, 0x74, 0x3A, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44
        };

        // -- GssChannelBindings hash computation tests --

        [TestMethod]
        public void ChannelBindings_ComputeHash_ReturnsFixedLength()
        {
            var bindings = new GssChannelBindings
            {
                ApplicationData = SampleTlsBinding
            };

            var hash = bindings.ComputeBindingHash();

            Assert.AreEqual(16, hash.Length); // MD5 always produces 16 bytes
        }

        [TestMethod]
        public void ChannelBindings_ComputeHash_Deterministic()
        {
            var bindings1 = new GssChannelBindings { ApplicationData = SampleTlsBinding };
            var bindings2 = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var hash1 = bindings1.ComputeBindingHash();
            var hash2 = bindings2.ComputeBindingHash();

            Assert.IsTrue(hash1.Span.SequenceEqual(hash2.Span));
        }

        [TestMethod]
        public void ChannelBindings_ComputeHash_DifferentData_DifferentHash()
        {
            var bindings1 = new GssChannelBindings { ApplicationData = new byte[] { 1, 2, 3 } };
            var bindings2 = new GssChannelBindings { ApplicationData = new byte[] { 4, 5, 6 } };

            var hash1 = bindings1.ComputeBindingHash();
            var hash2 = bindings2.ComputeBindingHash();

            Assert.IsFalse(hash1.Span.SequenceEqual(hash2.Span));
        }

        [TestMethod]
        public void ChannelBindings_ComputeHash_EmptyApplicationData()
        {
            var bindings = new GssChannelBindings();

            var hash = bindings.ComputeBindingHash();

            Assert.AreEqual(16, hash.Length);
        }

        [TestMethod]
        public void ChannelBindings_ComputeHash_AllFieldsPopulated()
        {
            var bindings = new GssChannelBindings
            {
                InitiatorAddrType = 2,
                InitiatorAddress = new byte[] { 127, 0, 0, 1 },
                AcceptorAddrType = 2,
                AcceptorAddress = new byte[] { 10, 0, 0, 1 },
                ApplicationData = SampleTlsBinding
            };

            var hash = bindings.ComputeBindingHash();

            Assert.AreEqual(16, hash.Length);

            // Verify it differs from application-data-only version
            var bindingsAppOnly = new GssChannelBindings { ApplicationData = SampleTlsBinding };
            var hashAppOnly = bindingsAppOnly.ComputeBindingHash();

            Assert.IsFalse(hash.Span.SequenceEqual(hashAppOnly.Span));
        }

        // -- DelegationInfo round-trip with channel bindings --

        [TestMethod]
        public void DelegationInfo_ChannelBindings_Roundtrip()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };
            var expectedHash = bindings.ComputeBindingHash();

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var delegInfo = new DelegationInfo(rst);

            Assert.AreEqual(16, delegInfo.ChannelBinding.Length);
            Assert.IsTrue(expectedHash.Span.SequenceEqual(delegInfo.ChannelBinding.Span));

            var encoded = delegInfo.Encode();
            var decoded = new DelegationInfo().Decode(encoded);

            Assert.IsTrue(expectedHash.Span.SequenceEqual(decoded.ChannelBinding.Span));
        }

        [TestMethod]
        public void DelegationInfo_NoChannelBindings_ZeroPadded()
        {
            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG
            };

            var delegInfo = new DelegationInfo(rst);

            // Should be zero-length before encoding
            Assert.AreEqual(0, delegInfo.ChannelBinding.Length);

            // After encoding/decoding it becomes 16 zero-bytes
            var encoded = delegInfo.Encode();
            var decoded = new DelegationInfo().Decode(encoded);

            Assert.AreEqual(16, decoded.ChannelBinding.Length);
            Assert.IsTrue(decoded.ChannelBinding.Span.SequenceEqual(new byte[16]));
        }

        // -- Authenticator checksum encoding with channel bindings --

        [TestMethod]
        public void AuthenticatorChecksum_ChannelBindings_InChecksum()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNotNull(authenticator.Checksum);
            Assert.AreEqual((ChecksumType)0x8003, authenticator.Checksum.Type);
        }

        // -- SEC_CHANNEL_BINDINGS parsing tests --

        [TestMethod]
        public void FromSecChannelBindings_ApplicationDataOnly()
        {
            // Build a SEC_CHANNEL_BINDINGS buffer with only ApplicationData populated
            var appData = SampleTlsBinding;
            var buffer = BuildSecChannelBindings(0, ReadOnlyMemory<byte>.Empty, 0, ReadOnlyMemory<byte>.Empty, appData);

            var bindings = GssChannelBindings.FromSecChannelBindings(buffer);

            Assert.AreEqual(0, bindings.InitiatorAddrType);
            Assert.AreEqual(0, bindings.InitiatorAddress.Length);
            Assert.AreEqual(0, bindings.AcceptorAddrType);
            Assert.AreEqual(0, bindings.AcceptorAddress.Length);
            Assert.IsTrue(bindings.ApplicationData.Span.SequenceEqual(appData));
        }

        [TestMethod]
        public void FromSecChannelBindings_AllFieldsPopulated()
        {
            var initiator = new byte[] { 127, 0, 0, 1 };
            var acceptor = new byte[] { 10, 0, 0, 1 };
            var appData = SampleTlsBinding;

            var buffer = BuildSecChannelBindings(2, initiator, 2, acceptor, appData);
            var bindings = GssChannelBindings.FromSecChannelBindings(buffer);

            Assert.AreEqual(2, bindings.InitiatorAddrType);
            Assert.IsTrue(bindings.InitiatorAddress.Span.SequenceEqual(initiator));
            Assert.AreEqual(2, bindings.AcceptorAddrType);
            Assert.IsTrue(bindings.AcceptorAddress.Span.SequenceEqual(acceptor));
            Assert.IsTrue(bindings.ApplicationData.Span.SequenceEqual(appData));
        }

        [TestMethod]
        public void FromSecChannelBindings_HashMatchesManualConstruction()
        {
            var appData = SampleTlsBinding;
            var buffer = BuildSecChannelBindings(0, ReadOnlyMemory<byte>.Empty, 0, ReadOnlyMemory<byte>.Empty, appData);

            var fromRaw = GssChannelBindings.FromSecChannelBindings(buffer);
            var manual = new GssChannelBindings { ApplicationData = appData };

            Assert.IsTrue(fromRaw.ComputeBindingHash().Span.SequenceEqual(manual.ComputeBindingHash().Span));
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void FromSecChannelBindings_BufferTooSmall_Throws()
        {
            GssChannelBindings.FromSecChannelBindings(new byte[16]);
        }

        [TestMethod]
        public void ExpectedRawChannelBindings_ValidatesCorrectly()
        {
            var appData = SampleTlsBinding;
            var rawBuffer = BuildSecChannelBindings(0, ReadOnlyMemory<byte>.Empty, 0, ReadOnlyMemory<byte>.Empty, appData);

            var bindings = new GssChannelBindings { ApplicationData = appData };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            // Use the raw buffer convenience method
            decrypted.SetExpectedChannelBindingsFromSecChannelBindings(rawBuffer);

            // Should not throw — hash matches
            decrypted.Validate(ValidationActions.ChannelBinding);
        }

        /// <summary>
        /// Builds a SEC_CHANNEL_BINDINGS flat buffer in the Windows SSPI layout.
        /// </summary>
        private static byte[] BuildSecChannelBindings(
            int initiatorAddrType, ReadOnlyMemory<byte> initiatorAddress,
            int acceptorAddrType, ReadOnlyMemory<byte> acceptorAddress,
            ReadOnlyMemory<byte> applicationData)
        {
            const int headerSize = 32;
            int offset = headerSize;

            int initiatorOffset = initiatorAddress.Length > 0 ? offset : 0;
            offset += initiatorAddress.Length;

            int acceptorOffset = acceptorAddress.Length > 0 ? offset : 0;
            offset += acceptorAddress.Length;

            int appDataOffset = applicationData.Length > 0 ? offset : 0;
            offset += applicationData.Length;

            var buffer = new byte[offset];

            using (var ms = new System.IO.MemoryStream(buffer))
            using (var writer = new System.IO.BinaryWriter(ms))
            {
                writer.Write(initiatorAddrType);
                writer.Write(initiatorAddress.Length);
                writer.Write(initiatorOffset);

                writer.Write(acceptorAddrType);
                writer.Write(acceptorAddress.Length);
                writer.Write(acceptorOffset);

                writer.Write(applicationData.Length);
                writer.Write(appDataOffset);

                if (initiatorAddress.Length > 0)
                {
                    writer.Write(initiatorAddress.ToArray());
                }

                if (acceptorAddress.Length > 0)
                {
                    writer.Write(acceptorAddress.ToArray());
                }

                if (applicationData.Length > 0)
                {
                    writer.Write(applicationData.ToArray());
                }
            }

            return buffer;
        }

        // -- Validation integration tests --

        [TestMethod]
        public void Validate_ChannelBinding_MatchingBindings_Succeeds()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            // Set matching expected bindings
            decrypted.ExpectedChannelBindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            // Should not throw
            decrypted.Validate(ValidationActions.ChannelBinding);
        }

        [TestMethod]
        [ExpectedException(typeof(KerberosValidationException))]
        public void Validate_ChannelBinding_MismatchedBindings_Throws()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            // Set different expected bindings
            decrypted.ExpectedChannelBindings = new GssChannelBindings
            {
                ApplicationData = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC }
            };

            // Should throw KerberosValidationException
            decrypted.Validate(ValidationActions.ChannelBinding);
        }

        [TestMethod]
        [ExpectedException(typeof(KerberosValidationException))]
        public void Validate_ChannelBinding_AcceptorExpects_InitiatorOmitted_Throws()
        {
            // Initiator does NOT supply channel bindings
            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            // Acceptor expects bindings
            decrypted.ExpectedChannelBindings = new GssChannelBindings
            {
                ApplicationData = SampleTlsBinding
            };

            // Should throw because initiator didn't supply bindings but acceptor expects them
            decrypted.Validate(ValidationActions.ChannelBinding);
        }

        [TestMethod]
        public void Validate_ChannelBinding_AcceptorDoesNotExpect_DoesNotThrowIfInitiatorSuppliesBindings()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            // Acceptor does NOT set expected bindings (null)
            decrypted.ExpectedChannelBindings = null;

            // Should not throw, acceptor doesn't require bindings
            decrypted.Validate(ValidationActions.ChannelBinding);
        }

        [TestMethod]
        public void Validate_ChannelBinding_NotInValidationActions_Skipped()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            // Set mismatched bindings but don't include ChannelBinding in validation flags
            decrypted.ExpectedChannelBindings = new GssChannelBindings
            {
                ApplicationData = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC }
            };

            // Should NOT throw, ChannelBinding validation is not requested
            decrypted.Validate(ValidationActions.ClientPrincipalIdentifier | ValidationActions.Realm);
        }

        [TestMethod]
        public void Validate_ChannelBinding_InAllActions_WithMatchingBindings()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            decrypted.ExpectedChannelBindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };

            // Validate with DefaultActions, which includes ChannelBinding
            decrypted.Validate(DefaultActions);
        }

        [TestMethod]
        public void ChannelBindingHash_Extracted_AfterDecrypt()
        {
            var bindings = new GssChannelBindings { ApplicationData = SampleTlsBinding };
            var expectedHash = bindings.ComputeBindingHash();

            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG,
                ChannelBindings = bindings
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            Assert.AreEqual(16, decrypted.ChannelBindingHash.Length);
            Assert.IsTrue(expectedHash.Span.SequenceEqual(decrypted.ChannelBindingHash.Span));
        }

        [TestMethod]
        public void ChannelBindingHash_AllZeros_WhenNoBindings()
        {
            var rst = new RequestServiceTicket
            {
                GssContextFlags = GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG
            };

            var apReq = GenerateApReqAndDecrypt(rst, out DecryptedKrbApReq decrypted);

            Assert.AreEqual(16, decrypted.ChannelBindingHash.Length);
            Assert.IsTrue(decrypted.ChannelBindingHash.Span.SequenceEqual(new byte[16]));
        }

        private static readonly KerberosKey ServiceKey = new KerberosKey(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96);

        private static KrbApReq GenerateApReq(RequestServiceTicket rst, out KrbAuthenticator authenticator)
        {
            var key = ServiceKey;

            var now = DateTimeOffset.UtcNow;
            var notBefore = now.AddMinutes(-5);
            var notAfter = now.AddMinutes(55);
            var renewUntil = now.AddMinutes(555);

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                Principal = new FakeKerberosPrincipal("test@test.com"),
                ServicePrincipal = new FakeKerberosPrincipal("host/test.com"),
                ServicePrincipalKey = key,
                IncludePac = false,
                RealmName = "test.com",
                ClientRealmName = "test.com",
                Now = now,
                StartTime = notBefore,
                EndTime = notAfter,
                RenewTill = renewUntil,
                Flags = TicketFlags.Renewable
            });

            // Extract the session key from the encrypted part
            // this is the key the KDC generated inside the ticket
            // that the service will use to decrypt the authenticator
            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                key,
                KeyUsage.EncTgsRepPartSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            var sessionKey = encKdcRepPart.Key.AsKey();

            return KrbApReq.CreateApReq(tgsRep, sessionKey, rst, out authenticator);
        }

        private static KrbApReq GenerateApReqAndDecrypt(RequestServiceTicket rst, out DecryptedKrbApReq decrypted)
        {
            var apReq = GenerateApReq(rst, out _);

            decrypted = new DecryptedKrbApReq(apReq);
            decrypted.Decrypt(ServiceKey);

            return apReq;
        }
    }
}
