// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AuthenticatorTests : BaseTest
    {
        private const string ApReqWithoutPacLogonInfo = "YIIDFwYGKwYBBQUCoIIDCzCCAwegDTALBgkqhkiG9xIBAgKiggL0BIIC8GCCAuwGCSqGSIb3EgECA" +
            "gEAboIC2zCCAtegAwIBBaEDAgEOogcDBQAgAAAAo4IBtGGCAbAwggGsoAMCAQWhHxsdQ09SUC5JREVOVElUWUlOVEVSVkVOVElPTi5DT02iWjBYoAMCAQKhUT" +
            "BPGwRob3N0GyhhcHBzZXJ2aWNlLmNvcnAuaWRlbnRpdHlpbnRlcnZlbnRpb24uY29tGx1DT1JQLklERU5USVRZSU5URVJWRU5USU9OLkNPTaOCASYwggEioAM" +
            "CARKiggEZBIIBFQ/VQjHzHo8Pjug4HAJMQ8sovdyLuCIiviMWD52cjBhpHlrWx+GX1ZLXpoXu0V95+T+VoVzdDulxPwBeeIMZRt5pKck1SphlRPlPqtpoOBgZ" +
            "dRqmZ3nFWKAg8VjE/bZIZGsQJasWoDc3brZcou64pp0Xwt6gc+VCkcVBbyicoHm32WpbJx0htgp1pdHEwsuDBn73ul36s/04uMq30iGW04DOY99/C3zTo6dMc" +
            "2ZB7tqAhZk7WMHzQ4nNsRp/Cp0WIkBQEAIDVllwI44vtnpMlESgiGgYWnjLOLnc+BX07m5IzWIxUISJSvJwydvMx6DC4ZTY3jG7fDCeLzqRju+NpqiAmTxJpw" +
            "oJE6+aEGjDvYqZZySLnv2kggEIMIIBBKADAgESooH8BIH5GG37GRQ4n6lrqYIQErjUAwMfe4DJtOp9U+CIGt/K1Oz9VbnVhj/o1Z3o/5hT29kIMocZ1UneO6s" +
            "iYgAqe9EWQxk4L0oro+9rLXBU48WGIytopEd6gs0PEdW/zya/pdW/evyb1JLuyqkMKYZlF6rXeSdgoMhq6bSnkJPTAdT7Baw5R3eCAu6jW/Ad/7Yyp7Y2/nfk" +
            "e0P5Nfw135/dhEuPMcDs/2HBHHgKEV9sAMqKQQKKTt9ZB6jFJE0wSk4ULPUgfJrGIeouxHjv2lgrG42rPehB+8wvyHoucocwUlgMsgwthDtrynae4KxDKX9k2" +
            "RXlv1dmdYUHwQ3M";

        [TestMethod]
        public async Task AuthenticatorGetsApRep()
        {
            var authenticator = new KerberosAuthenticator(
                new KerberosValidator(new KeyTable(ReadDataFile("sample.keytab")))
                {
                    ValidateAfterDecrypt = DefaultActions
                });

            Assert.IsNotNull(authenticator);

            var result = await authenticator.Authenticate(RC4Header) as KerberosIdentity;

            Assert.IsNotNull(result);

            Assert.IsNotNull(result.ApRep);
        }

        [TestMethod]
        public async Task Authenticator_Default()
        {
            var authenticator = new KerberosAuthenticator(
                new KerberosValidator(new KeyTable(ReadDataFile("sample.keytab")))
                {
                    ValidateAfterDecrypt = DefaultActions
                });

            Assert.IsNotNull(authenticator);

            var result = await authenticator.Authenticate(RC4Header);

            Assert.IsNotNull(result);

            Assert.AreEqual("Administrator@identityintervention.com", result.Name);
            Assert.AreEqual(27, result.Claims.Count());
        }

        [TestMethod]
        public async Task Authenticator_DownLevelNameFormat()
        {
            var authenticator = new KerberosAuthenticator(
                new KerberosValidator(new KeyTable(ReadDataFile("sample.keytab")))
                {
                    ValidateAfterDecrypt = DefaultActions
                })
            {
                UserNameFormat = UserNameFormat.DownLevelLogonName
            };

            var result = await authenticator.Authenticate(RC4Header);

            Assert.IsNotNull(result);
            Assert.AreEqual(@"IDENTITYINTER\Administrator", result.Name);
        }

        private static readonly IEnumerable<string> KnownMechTypes = new[]
        {
            "1.3.6.1.5.5.2",
            "1.2.840.48018.1.2.2",
            "1.2.840.113554.1.2.2",
            "1.2.840.113554.1.2.2.3",
            "1.3.6.1.4.1.311.2.2.10",
            "1.3.6.1.4.1.311.2.2.30"
        };

        [TestMethod]
        public void MechTypes()
        {
            foreach (var mechType in KnownMechTypes)
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(MechType.LookupOid(mechType)));
            }
        }

        [TestMethod]
        public void UnknownMechType()
        {
            Assert.IsTrue(string.IsNullOrEmpty(MechType.LookupOid("1.2.3.4.5.6.7.8.9")));
        }

        [TestMethod]
        public async Task KrbApReqWithoutPacLogonInfo()
        {
            var data = Convert.FromBase64String(ApReqWithoutPacLogonInfo);
            var key = new KeyTable(
                new KerberosKey(
                    "P@ssw0rd!",
                    principalName: new PrincipalName(
                        PrincipalNameType.NT_PRINCIPAL,
                        "corp.identityintervention.com",
                        new[] { "host/appservice.corp.identityintervention.com" }
                    ),
                    saltType: SaltType.ActiveDirectoryUser
                )
            );

            var authenticator = new KerberosAuthenticator(new KerberosValidator(key) { ValidateAfterDecrypt = DefaultActions });

            var result = await authenticator.Authenticate(data);

            Assert.IsNotNull(result);

            Assert.AreEqual(1, result.Claims.Count());

            Assert.AreEqual("administrator@CORP.IDENTITYINTERVENTION.COM", result.Name);
        }

        [TestMethod]
        public void KrbAuthenticator_Roundtrip()
        {
            var auth = new KrbAuthenticator
            {
                AuthorizationData = new[] { new KrbAuthorizationData { Data = new byte[16], Type = AuthorizationDataType.AdAndOr } },
                Checksum = KrbChecksum.Create(new byte[16], new KerberosKey(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96), KeyUsage.AdKdcIssuedChecksum),
                CName = KrbPrincipalName.FromString("blah@blah.com"),
                CTime = DateTimeOffset.UtcNow,
                CuSec = 1234,
                Realm = "blah.com",
                SequenceNumber = 123456,
                Subkey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96)
            };

            var encoded = auth.EncodeApplication();

            var decoded = KrbAuthenticator.DecodeApplication(encoded);

            Assert.IsNotNull(decoded);
            Assert.IsNotNull(decoded.AuthorizationData);
            Assert.AreEqual(1, decoded.AuthorizationData.Length);
            Assert.AreEqual(AuthorizationDataType.AdAndOr, decoded.AuthorizationData[0].Type);
            Assert.AreEqual("blah@blah.com", decoded.CName.FullyQualifiedName);
        }

        [TestMethod]
        public void AuthenticatorChecksum_GssDefaults()
        {
            var rst = new RequestServiceTicket { };
            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNotNull(authenticator.Checksum);
            Assert.AreEqual((ChecksumType)32771, authenticator.Checksum.Type);
        }

        [TestMethod]
        public void AuthenticatorChecksum_NonceDefaults()
        {
            var rst = new RequestServiceTicket { };
            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNotNull(authenticator.Checksum);
            Assert.IsNotNull(authenticator.SequenceNumber);
            Assert.AreNotEqual(0, authenticator.SequenceNumber.Value);
        }

        [TestMethod]
        public void AuthenticatorChecksum_NoNonce()
        {
            var rst = new RequestServiceTicket { IncludeSequenceNumber = false };
            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNotNull(authenticator.Checksum);
            Assert.IsNull(authenticator.SequenceNumber);
        }

        [TestMethod]
        public void AuthenticatorChecksum_GssEmpty()
        {
            var rst = new RequestServiceTicket { GssContextFlags = GssContextEstablishmentFlag.GSS_C_NONE };
            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNull(authenticator.Checksum);
        }

        [TestMethod]
        public void AuthenticatorChecksum_AppChecksum()
        {
            var rst = new RequestServiceTicket
            {
                AuthenticatorChecksum = new KrbChecksum
                {
                    Type = ChecksumType.HMAC_SHA256_128_AES128,
                    Checksum = new byte[245]
                }
            };

            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNotNull(authenticator.Checksum);

            Assert.AreEqual(ChecksumType.HMAC_SHA256_128_AES128, authenticator.Checksum.Type);

            Assert.IsTrue(
                KerberosCryptoTransformer.AreEqualSlow(
                    new byte[245],
                    authenticator.Checksum.Checksum.Span
                )
            );
        }

        [TestMethod]
        public void AuthenticatorChecksum_ChecksumSource()
        {
            var key = new KerberosKey(key: new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            var rst = new RequestServiceTicket { AuthenticatorChecksumSource = new byte[345] };
            KrbApReq apreq = GenerateApReq(rst, out KrbAuthenticator authenticator);

            Assert.IsNotNull(apreq);
            Assert.IsNotNull(authenticator);
            Assert.IsNotNull(authenticator.Checksum);

            var expected = KrbChecksum.Create(
                rst.AuthenticatorChecksumSource,
                key,
                KeyUsage.AuthenticatorChecksum
            );

            Assert.IsTrue(
                KerberosCryptoTransformer.AreEqualSlow(
                    expected.Checksum.Span,
                    authenticator.Checksum.Checksum.Span
                )
            );
        }

        private static KrbApReq GenerateApReq(RequestServiceTicket rst, out KrbAuthenticator authenticator)
        {
            var key = new KerberosKey(key: new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            var now = DateTimeOffset.UtcNow;
            var notBefore = now.AddMinutes(-5);
            var notAfter = now.AddMinutes(55);
            var renewUntil = now.AddMinutes(555);

            var tgsRep = KrbTgsRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
            {
                EncryptedPartKey = key,
                Principal = new FakeKerberosPrincipal("test@test.com"),
                ServicePrincipal = new FakeKerberosPrincipal("host/test.com"),
                ServicePrincipalKey = key,
                IncludePac = false,
                RealmName = "test.com",
                Now = now,
                StartTime = notBefore,
                EndTime = notAfter,
                RenewTill = renewUntil,
                Flags = TicketFlags.Renewable
            });

            return KrbApReq.CreateApReq(tgsRep, key, rst, out authenticator);
        }
    }
}
