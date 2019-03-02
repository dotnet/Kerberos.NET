using Kerberos.NET;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Globalization;
using System.Linq;
using System.Security;
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
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.Replay };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async Task TestKerberosValidatorNone()
        {
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.None };

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod]
        public async Task TestKerberosValidatorTimeOffset()
        {
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            validator.Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture);

            var result = await validator.Validate(data);

            Assert.IsNotNull(result);
        }

        [TestMethod, ExpectedException(typeof(SecurityException))]
        public async Task TestKerberosValidatorBadKey()
        {
            var data = ReadFile("aes128-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            await validator.Validate(data);
        }

        [TestMethod, ExpectedException(typeof(KerberosValidationException))]
        public async Task TestKerberosValidatorExpiredTicket()
        {
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            await validator.Validate(data);
        }

        [TestMethod, ExpectedException(typeof(ReplayException))]
        public async Task TestValidatorReplayCache()
        {
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key);

            validator.Now = () => DateTimeOffset.Parse("1/9/2009 5:20:00 PM +00:00", CultureInfo.InvariantCulture);


            await validator.Validate(data);

            await validator.Validate(data);
        }

        [TestMethod]
        public async Task TestValidatorMemoryCacheExpiration()
        {
            var replay = new TicketReplayValidator();

            var entry = new TicketCacheEntry {
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

        [TestMethod]
        public async Task TestValidatorCheckPacLogonInfo()
        {
            var data = ReadFile("rc4-kerberos-data");
            var key = ReadFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.Replay };
            var result = await validator.Validate(data);
            var pac = (PacElement)result.Ticket.AuthorizationData
                .Select(d => d.Authorizations.First(a => a.Type == AuthorizationDataValueType.AD_WIN2K_PAC))
                .First();

            var expectedLogonTime = DateTimeOffset.Parse("1/9/2009 5:15:20 PM +00:00", CultureInfo.InvariantCulture);
            var logonInfo = pac.Certificate.LogonInfo;
            Assert.AreEqual(expectedLogonTime, Truncate(logonInfo.LogonTime));
            var expectedLogoffTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLogoffTime, logonInfo.LogoffTime);
            var expectedKickOffTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedKickOffTime, logonInfo.KickOffTime);
            var expectedPwdLastChangeTime = DateTimeOffset.Parse("1/7/2009 2:33:58 PM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdLastChangeTime, Truncate(logonInfo.PwdLastChangeTime));
            var expectedPwdCanChangeTime = DateTimeOffset.Parse("1/8/2009 2:33:58 PM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdCanChangeTime, Truncate(logonInfo.PwdCanChangeTime));
            var expectedPwdMustChangeTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdMustChangeTime, logonInfo.PwdMustChangeTime);
            Assert.AreEqual(46, logonInfo.LogonCount);
            Assert.AreEqual(0, logonInfo.BadPasswordCount);
            Assert.AreEqual(UserFlags.LOGON_EXTRA_SIDS, logonInfo.UserFlags);
            Assert.AreEqual(UserAccountControlFlags.ADS_UF_LOCKOUT | UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT,
                logonInfo.UserAccountControl);
            Assert.AreEqual(0, logonInfo.SubAuthStatus);
            var expectedLastSuccessfulILogon = DateTimeOffset.Parse("1/1/1601 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLastSuccessfulILogon, logonInfo.LastSuccessfulILogon);
            var expectedLastLastFailedILogon = DateTimeOffset.Parse("1/1/1601 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLastLastFailedILogon, logonInfo.LastFailedILogon);
            Assert.AreEqual("user.test", logonInfo.UserName);
            Assert.AreEqual("User Test", logonInfo.UserDisplayName);
            Assert.AreEqual("", logonInfo.LogonScript);
            Assert.AreEqual("", logonInfo.ProfilePath);
            Assert.AreEqual("", logonInfo.HomeDirectory);
            Assert.AreEqual("", logonInfo.HomeDrive);
            Assert.AreEqual("WS2008", logonInfo.ServerName);
            Assert.AreEqual("DOMAIN", logonInfo.DomainName);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075", logonInfo.DomainSid.Value);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075-1106", logonInfo.UserSid.Value);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075-513", logonInfo.GroupSid.Value);
            Assert.AreEqual(11, logonInfo.GroupSids.Count());
            Assert.AreEqual(7, logonInfo.ExtraSids.Count());
            Assert.IsNull(logonInfo.ResourceDomainSid);
            Assert.IsNull(logonInfo.ResourceGroups);
        }

        private DateTimeOffset Truncate(DateTimeOffset dateTime)
        {
            if (dateTime == DateTimeOffset.MinValue || dateTime == DateTimeOffset.MaxValue)
            {
                return dateTime;
            }

            return dateTime.AddTicks(-(dateTime.Ticks % TimeSpan.FromSeconds(1).Ticks));
        }
    }
}
