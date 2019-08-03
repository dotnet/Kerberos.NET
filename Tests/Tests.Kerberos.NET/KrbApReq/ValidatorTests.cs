using Kerberos.NET;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;

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

        internal class TestLogger : ILogger
        {
            public TestLogger()
            {
                Logs = new List<string>();
            }

            public LogLevel Level { get; set; } = LogLevel.Debug;

            public bool Enabled { get; set; } = true;

            public List<string> Logs { get; }

            public void WriteLine(KerberosLogSource source, string value)
            {
                Logs.Add($"[{source}] {value}");
            }

            public void WriteLine(KerberosLogSource source, string value, Exception ex)
            {
                Logs.Add($"[{source}] {value} {ex}");
            }

            public void WriteLine(KerberosLogSource source, Exception ex)
            {
                Logs.Add($"[{source}] {ex}");
            }
        }

        [TestMethod]
        public async Task TestValidatorMemoryCacheExpiration()
        {
            var logger = new TestLogger();

            var replay = new TicketReplayValidator(logger);

            var entry = new TicketCacheEntry
            {
                Key = "blargh",
                Expires = DateTimeOffset.UtcNow.AddHours(1)
            };

            var added = await replay.Add(entry);

            Assert.IsTrue(added);

            Assert.AreEqual(1, logger.Logs.Count);

            added = await replay.Add(entry);

            Assert.IsFalse(added);
        }

        [TestMethod]
        public async Task TestValidatorMemoryCacheExpirationExpired()
        {
            var logger = new TestLogger();

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

            Assert.AreEqual(2, logger.Logs.Count);
        }
    }
}
