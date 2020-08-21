using System;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ValidatorTests : BaseTest
    {
        [TestMethod]
        public async Task KerberosValidator()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async Task KerberosValidatorNone()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.None };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async Task KerberosValidatorTimeOffset()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key)
            {
                Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture)
            };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public async Task KerberosValidatorExpiredTicket()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            await validator.Validate(data);
        }

        [TestMethod, ExpectedException(typeof(ReplayException))]
        public async Task ValidatorReplayCache()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key)
            {
                Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture)
            };

            await validator.Validate(data);

            await validator.Validate(data);
        }

        [TestMethod]
        public async Task ValidatorMemoryCacheExpiration()
        {
            var logger = new FakeExceptionLoggerFactory();

            var replay = new TicketReplayValidator(logger);

            var entry = new TicketCacheEntry
            {
                Key = "blargh",
                Expires = DateTimeOffset.UtcNow.AddHours(1)
            };

            var added = await replay.Add(entry);

            Assert.IsTrue(added);

            Assert.IsTrue(logger.Logs.Count() > 0);

            added = await replay.Add(entry);

            Assert.IsFalse(added);
        }

        [TestMethod]
        public async Task ValidatorMemoryCacheExpirationExpired()
        {
            var logger = new FakeExceptionLoggerFactory();

            var replay = new TicketReplayValidator(logger);

            var entry = new TicketCacheEntry
            {
                Key = "blargh",
                Expires = DateTimeOffset.UtcNow.AddMilliseconds(100)
            };

            var added = await replay.Add(entry);

            Assert.IsTrue(added);

            await Task.Delay(TimeSpan.FromSeconds(1));

            added = await replay.Add(entry);

            Assert.IsTrue(added);

            Assert.IsTrue(logger.Logs.Count() > 1);
        }

        [TestMethod]
        public void KrbEncApRepPartRoundtrip()
        {
            var encPart = new KrbEncApRepPart
            {
                CTime = DateTimeOffset.UtcNow,
                CuSec = 123,
                SequenceNumber = 123,
                SubSessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96)
            };

            var encoded = encPart.EncodeApplication();

            var decoded = KrbEncApRepPart.DecodeApplication(encoded);

            Assert.IsNotNull(decoded);
            Assert.AreEqual(123, decoded.CuSec);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApReq_Validate_NotBefore()
        {
            // generate ticket for the future

            var now = DateTimeOffset.UtcNow;
            var notBefore = DateTimeOffset.UtcNow.AddMinutes(30);
            var notAfter = DateTimeOffset.UtcNow;
            var renewUntil = DateTimeOffset.UtcNow;

            DecryptedKrbApReq decrypted = CreateDecryptedApReq(now, notBefore, notAfter, renewUntil);

            decrypted.Validate(ValidationActions.All);
        }

        private static DecryptedKrbApRep CreateResponseMessage(DateTimeOffset ctime, int cusec, int sequence, KerberosKey sessionKey)
        {
            var apRepPart = new KrbEncApRepPart
            {
                CTime = ctime,
                CuSec = cusec,
                SequenceNumber = sequence
            };

            var apRep = new KrbApRep
            {
                EncryptedPart = KrbEncryptedData.Encrypt(
                    apRepPart.EncodeApplication(),
                    sessionKey,
                    KeyUsage.EncApRepPart
                )
            };

            var decrypted = new DecryptedKrbApRep(apRep);

            decrypted.Decrypt(sessionKey);

            return decrypted;
        }

        private static DecryptedKrbApReq CreateDecryptedApReq(DateTimeOffset now, DateTimeOffset notBefore, DateTimeOffset notAfter, DateTimeOffset renewUntil)
        {
            var key = new KerberosKey(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96);

            var tgsRep = KrbKdcRep.GenerateServiceTicket<KrbTgsRep>(new ServiceTicketRequest
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

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                key,
                KeyUsage.EncTgsRepPartSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            var apReq = KrbApReq.CreateApReq(tgsRep, encKdcRepPart.Key.AsKey(), default, out KrbAuthenticator authenticator);

            var decrypted = new DecryptedKrbApReq(apReq);

            decrypted.Decrypt(key);
            return decrypted;
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApReq_Validate_NotAfter()
        {
            // generate ticket for the past

            var now = DateTimeOffset.UtcNow;
            var notBefore = DateTimeOffset.UtcNow.AddMinutes(-45);
            var notAfter = DateTimeOffset.UtcNow.AddMinutes(-30);
            var renewUntil = DateTimeOffset.UtcNow;

            DecryptedKrbApReq decrypted = CreateDecryptedApReq(now, notBefore, notAfter, renewUntil);

            decrypted.Validate(ValidationActions.All);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApReq_Validate_RenewUntil()
        {
            // generate ticket for the future

            var now = DateTimeOffset.UtcNow;
            var notBefore = DateTimeOffset.UtcNow;
            var notAfter = DateTimeOffset.UtcNow.AddMinutes(30);
            var renewUntil = DateTimeOffset.UtcNow.AddMinutes(-30);

            DecryptedKrbApReq decrypted = CreateDecryptedApReq(now, notBefore, notAfter, renewUntil);

            decrypted.Validate(ValidationActions.All);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApReq_Validate_Skew()
        {
            // generate ticket where now is ten minutes ago

            var now = DateTimeOffset.UtcNow;
            var notBefore = DateTimeOffset.UtcNow.AddHours(-1);
            var notAfter = DateTimeOffset.UtcNow.AddMinutes(30);
            var renewUntil = DateTimeOffset.UtcNow.AddMinutes(30);

            DecryptedKrbApReq decrypted = CreateDecryptedApReq(now, notBefore, notAfter, renewUntil);

            decrypted.Now = () => DateTimeOffset.UtcNow.AddMinutes(-10);

            decrypted.Validate(ValidationActions.All);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApRep_Validate_Skew()
        {
            // generate ticket where now is ten minutes ago

            var now = DateTimeOffset.UtcNow;

            var sessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96);

            var decrypted = CreateResponseMessage(now, 0, 123, sessionKey.AsKey());

            decrypted.Now = () => DateTimeOffset.UtcNow.AddMinutes(-10);

            decrypted.Validate(ValidationActions.All);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApRep_Validate_CTime()
        {
            var now = DateTimeOffset.UtcNow;

            var sessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96);

            var decrypted = CreateResponseMessage(now, 0, 123, sessionKey.AsKey());

            decrypted.Validate(ValidationActions.All);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApRep_Validate_CuSec()
        {
            var now = DateTimeOffset.UtcNow;

            var sessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96);

            var decrypted = CreateResponseMessage(now, 111, 123, sessionKey.AsKey());

            decrypted.CTime = now;

            decrypted.Validate(ValidationActions.All);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public void DecryptedKrbApRep_Validate_Sequence()
        {
            var now = DateTimeOffset.UtcNow;

            var sessionKey = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96);

            var decrypted = CreateResponseMessage(now, 111, 123, sessionKey.AsKey());

            decrypted.CTime = now;
            decrypted.CuSec = 111;

            decrypted.Validate(ValidationActions.All);
        }
    }
}
