using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

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

            var validator = new KerberosValidator(key);

            validator.Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture);

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

            var validator = new KerberosValidator(key);

            validator.Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture);


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

            Assert.AreEqual(1, logger.Logs.Count());

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

            await Task.Delay(TimeSpan.FromSeconds(5));

            added = await replay.Add(entry);

            Assert.IsTrue(added);

            Assert.AreEqual(2, logger.Logs.Count());
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

            var encoded = encPart.Encode();

            var decoded = KrbEncApRepPart.DecodeApplication(encoded.AsMemory());

            Assert.IsNotNull(decoded);
        }
    }
}
