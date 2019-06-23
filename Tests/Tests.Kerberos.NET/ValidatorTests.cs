using Kerberos.NET;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Authorization;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ValidatorTests : BaseTest
    {
        [TestMethod]
        public async Task TestKerberosValidator()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async Task TestKerberosValidatorNone()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.None };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async Task TestKerberosValidatorTimeOffset()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            validator.Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture);

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public async Task TestKerberosValidatorExpiredTicket()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            await validator.Validate(data);
        }

        [TestMethod, ExpectedException(typeof(ReplayException))]
        public async Task TestValidatorReplayCache()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            validator.Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture);


            await validator.Validate(data);

            await validator.Validate(data);
        }

        [TestMethod]
        public async Task TestValidatorMemoryCacheExpiration()
        {
            var replay = new TicketReplayValidator();

            var entry = new TicketCacheEntry
            {
                Key = "blargh",
                Expires = DateTimeOffset.UtcNow.AddHours(1)
            };

            var added = await replay.Add(entry);

            Assert.IsTrue(added);

            added = await replay.Add(entry);

            Assert.IsFalse(added);
        }

        [TestMethod]
        public async Task TestValidatorMemoryCacheExpirationExpired()
        {
            var replay = new TicketReplayValidator();

            var entry = new TicketCacheEntry
            {
                Key = "blargh",
                Expires = DateTimeOffset.UtcNow.AddSeconds(1)
            };

            var added = await replay.Add(entry);

            Assert.IsTrue(added);

            await Task.Delay(TimeSpan.FromSeconds(3));

            added = await replay.Add(entry);

            Assert.IsTrue(added);
        }
    }
}
