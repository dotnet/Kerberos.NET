using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Globalization;
using System.Linq;
using System.Security;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class PacTests : BaseTest
    {
        private const string RC4_PAC_SIGNATURE = "dv///9uwIJUdzAWaCdn16YcrrEk=";
        private const string
            RC4_PAC = "BQAAAAAAAAABAAAAIAMAAFgAAAAAAAAACgAAABwAAAB4AwAAAAAAAAwAAABQAAAAmAMAAAAAAAAGAAAAFAAAAOgDAAAAAAAABwAA" +
                "ABQAAAAABAAAAAAAAAEQCADMzMzMEAMAAAAAAAAAAAIAYE1z2X1yyQH/////////f/////////9/sFbR+dRwyQGwFjsknnHJAf////////" +
                "9/EgASAAQAAgASABIACAACAAAAAAAMAAIAAAAAABAAAgAAAAAAFAACAAAAAAAYAAIALgAAAFIEAAABAgAACwAAABwAAgAgAAAAAAAAAAAA" +
                "AAAAAAAAAAAAAAwADgAgAAIADAAOACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAsAAIAAA" +
                "AAAAAAAAAAAAAACQAAAAAAAAAJAAAAdQBzAGUAcgAuAHQAZQBzAHQAAAAJAAAAAAAAAAkAAABVAHMAZQByACAAVABlAHMAdAAAAAAAAAAA" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAACAgAABwAAAFAEAAAHAAAAAQIAAAcAAAAEAgAABwAAAA" +
                "MCAAAHAAAACAIAAAcAAAAAAgAABwAAAAkCAAAHAAAABgIAAAcAAAAHAgAABwAAAPIBAAAHAAAABwAAAAAAAAAGAAAAVwBTADIAMAAwADgA" +
                "BwAAAAAAAAAGAAAARABPAE0AQQBJAE4ABAAAAAEEAAAAAAAFFQAAAELcI/DfA8DDi6apKQcAAAAwAAIABwAAIDQAAgAHAAAgOAACAAcAAC" +
                "A8AAIABwAAIEAAAgAHAAAgRAACAAcAACBIAAIABwAAIAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSk8AgAABQAAAAEFAAAAAAAFFQAA" +
                "AELcI/DfA8DDi6apKTsCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkp6QMAAAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSnoAw" +
                "AABQAAAAEFAAAAAAAFFQAAAELcI / DfA8DDi6apKQUCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkpTwQAAAUAAAABBQAAAAAABR" +
                "UAAABC3CPw3wPAw4umqSkpAgAAAL9Len5yyQESAHUAcwBlAHIALgB0AGUAcwB0AAAAAAAoABAAFAA4AAAAAAAAAAAAdQBzAGUAcgAuAHQA" +
                "ZQBzAHQAQABkAG8AbQBhAGkAbgAuAGMAbwBtAEQATwBNAEEASQBOAC4AQwBPAE0AAAAAAHb///8AAAAAAAAAAAAAAAAAAAAAAAAAAHb//" +
                "/8AAAAAAAAAAAAAAAAAAAAAAAAAAA==";

        private const string AES128_PAC_SIGNATURE = "DwAAAKPYyDLq7MP4qie/GQ==";
        private const string AES128_PAC =
           "BQAAAAAAAAABAAAAIAMAAFgAAAAAAAAACgAAABwAAAB4AwAAAAAAAAwAAABQAAAAmAMAAAAAAAAGAAAAEAAAAOgDAAAAAAAA" +
          "BwAAABQAAAD4AwAAAAAAAAEQCADMzMzMEAMAAAAAAAAAAAIAwAycyX9yyQH/////////f/////////9/4Cg/sn9yyQHg6KjcS" +
          "HPJAf////////9/EgASAAQAAgASABIACAACAAAAAAAMAAIAAAAAABAAAgAAAAAAFAACAAAAAAAYAAIAMgAAAFIEAAABAgAACw" +
          "AAABwAAgAgAAAAAAAAAAAAAAAAAAAAAAAAAAwADgAgAAIADAAOACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAA" +
          "AAAAAAAAAAAAAAAAAAAcAAAAsAAIAAAAAAAAAAAAAAAAACQAAAAAAAAAJAAAAdQBzAGUAcgAuAHQAZQBzAHQAAAAJAAAAAAAA" +
          "AAkAAABVAHMAZQByACAAVABlAHMAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
          "AsAAAACAgAABwAAAFAEAAAHAAAAAQIAAAcAAAAEAgAABwAAAAMCAAAHAAAACAIAAAcAAAAAAgAABwAAAAkCAAAHAAAABgIAAA" +
          "cAAAAHAgAABwAAAPIBAAAHAAAABwAAAAAAAAAGAAAAVwBTADIAMAAwADgABwAAAAAAAAAGAAAARABPAE0AQQBJAE4ABAAAAAE" +
          "EAAAAAAAFFQAAAELcI/DfA8DDi6apKQcAAAAwAAIABwAAIDQAAgAHAAAgOAACAAcAACA8AAIABwAAIEAAAgAHAAAgRAACAAcA" +
          "ACBIAAIABwAAIAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSk8AgAABQAAAAEFAAAAAAAFFQAAAELcI/DfA8DDi6apKTsCA" +
          "AAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkp6QMAAAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSnoAwAABQAAAAEFAA" +
          "AAAAAFFQAAAELcI / DfA8DDi6apKQUCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkpTwQAAAUAAAABBQAAAAAABRUAA" +
          "ABC3CPw3wPAw4umqSkpAgAAgEkh / X9yyQESAHUAcwBlAHIALgB0AGUAcwB0AAAAAAAoABAAFAA4AAAAAAAAAAAAdQBzAGUA" +
          "cgAuAHQAZQBzAHQAQABkAG8AbQBhAGkAbgAuAGMAbwBtAEQATwBNAEEASQBOAC4AQwBPAE0AAAAAAA8AAAAAAAAAAAAAAAAAA" +
          "AB2////AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        private const string AES256_PAC_SIGNATURE = "EAAAAHcQyvz922ZFzfua7A==";
        private const string AES256_PAC
                = "BQAAAAAAAAABAAAAIAMAAFgAAAAAAAAACgAAABwAAAB4AwAAAAAAAAwAAABQAAAAmAMAAAAAAAAGAAAAEAAAAOgDAAAAAAAAB" +
            "wAAABQAAAD4AwAAAAAAAAEQCADMzMzMEAMAAAAAAAAAAAIAsITafH9yyQH/////////f/////////9/4Cg/sn9yyQHg6KjcSHPJAf//" +
            "//////9/EgASAAQAAgASABIACAACAAAAAAAMAAIAAAAAABAAAgAAAAAAFAACAAAAAAAYAAIAMQAAAFIEAAABAgAACwAAABwAAgAgAAA" +
            "AAAAAAAAAAAAAAAAAAAAAAAwADgAgAAIADAAOACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
            "cAAAAsAAIAAAAAAAAAAAAAAAAACQAAAAAAAAAJAAAAdQBzAGUAcgAuAHQAZQBzAHQAAAAJAAAAAAAAAAkAAABVAHMAZQByACAAVABlA" +
            "HMAdAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsAAAACAgAABwAAAFAEAAAHAAAAAQIA" +
            "AAcAAAAEAgAABwAAAAMCAAAHAAAACAIAAAcAAAAAAgAABwAAAAkCAAAHAAAABgIAAAcAAAAHAgAABwAAAPIBAAAHAAAABwAAAAAAAAA" +
            "GAAAAVwBTADIAMAAwADgABwAAAAAAAAAGAAAARABPAE0AQQBJAE4ABAAAAAEEAAAAAAAFFQAAAELcI/DfA8DDi6apKQcAAAAwAAIABw" +
            "AAIDQAAgAHAAAgOAACAAcAACA8AAIABwAAIEAAAgAHAAAgRAACAAcAACBIAAIABwAAIAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umq" +
            "Sk8AgAABQAAAAEFAAAAAAAFFQAAAELcI/DfA8DDi6apKTsCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8N8DwMOLpqkp6QMAAAUAAAABBQAA" +
            "AAAABRUAAABC3CPw3wPAw4umqSnoAwAABQAAAAEFAAAAAAAFFQAAAELcI / DfA8DDi6apKQUCAAAFAAAAAQUAAAAAAAUVAAAAQtwj8" +
            "N8DwMOLpqkpTwQAAAUAAAABBQAAAAAABRUAAABC3CPw3wPAw4umqSkpAgAAACRGyX9yyQESAHUAcwBlAHIALgB0AGUAcwB0AAAAAAAo" +
            "ABAAFAA4AAAAAAAAAAAAdQBzAGUAcgAuAHQAZQBzAHQAQABkAG8AbQBhAGkAbgAuAGMAbwBtAEQATwBNAEEASQBOAC4AQwBPAE0AAAA" +
            "AABAAAAAAAAAAAAAAAAAAAAB2////AAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        [TestMethod, ExpectedException(typeof(SecurityException))]
        public async Task KerberosValidatorBadKey()
        {
            var data = ReadDataFile("aes128-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = DefaultActions };

            await validator.Validate(data);
        }

        [TestMethod, ExpectedException(typeof(SecurityException))]
        public void KerberosValidatorAes128ModifiedPac()
        {
            var key = ReadDataFile("aes128-key-data");

            var kerbKey = new KerberosKey(key);

            var pacValidated = ValidatePac(
                kerbKey,
                Convert.FromBase64String(AES128_PAC_SIGNATURE),
                Convert.FromBase64String(AES128_PAC)
            );

            Assert.IsTrue(pacValidated);

            GenerateCorruptPac(AES128_PAC_SIGNATURE, AES128_PAC).Validator.Validate(kerbKey);
        }

        [TestMethod, ExpectedException(typeof(SecurityException))]
        public void KerberosValidatorAes256ModifiedPac()
        {
            var key = ReadDataFile("aes256-key-data");

            var kerbKey = new KerberosKey(key);

            var pacValidated = ValidatePac(
                kerbKey,
                Convert.FromBase64String(AES256_PAC_SIGNATURE),
                Convert.FromBase64String(AES256_PAC)
            );

            Assert.IsTrue(pacValidated);

            GenerateCorruptPac(AES256_PAC_SIGNATURE, AES256_PAC).Validator.Validate(kerbKey);
        }

        [TestMethod, ExpectedException(typeof(SecurityException))]
        public void KerberosValidatorRC4ModifiedPac()
        {
            var key = ReadDataFile("rc4-key-data");
            var kerbKey = new KerberosKey(key);

            var pacValidated = ValidatePac(
                kerbKey,
                Convert.FromBase64String(RC4_PAC_SIGNATURE),
                Convert.FromBase64String(RC4_PAC)
            );

            Assert.IsTrue(pacValidated);

            GenerateCorruptPac(RC4_PAC_SIGNATURE, RC4_PAC).Validator.Validate(kerbKey);
        }

        private static bool ValidatePac(KerberosKey kerbKey, byte[] infoBufferBytes, byte[] pacBytes)
        {
            bool pacValidated;

            try
            {
                var sig = new PacSignature(pacBytes);
                sig.Unmarshal(infoBufferBytes);
                sig.Validator.Validate(kerbKey);
                pacValidated = true;
            }
            catch (Exception)
            {
                pacValidated = false;
            }

            return pacValidated;
        }

        private static PacSignature GenerateCorruptPac(string infoBuffer, string pac)
        {
            var infoBufferBytes = Convert.FromBase64String(infoBuffer);
            var pacBytes = Convert.FromBase64String(pac);

            var rand = new Random();

            for (var i = 20; i < 50; i++)
            {
                pacBytes[i] = (byte)rand.Next(0, 254);
            }

            var sig = new PacSignature(pacBytes);
            sig.Unmarshal(infoBufferBytes);

            return sig;
        }

        [TestMethod]
        public async Task PacRoundtrip()
        {
            var keyBytes = ReadDataFile("rc4-key-data");
            var key = new KerberosKey(keyBytes, etype: EncryptionType.RC4_HMAC_NT);

            var pac = await GeneratePac();

            var encoded = pac.Encode(key, key);

            var pacDecoded = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = encoded });

            ;

            pacDecoded.ServerSignature.Validator.Validate(key);
            pacDecoded.KdcSignature.Validator.Validate(key);
        }

        [TestMethod]
        public async Task ValidatorCheckPacLogonInfo()
        {
            var cert = await GeneratePac();

            var logonInfo = cert.LogonInfo;

            var expectedLogonTime = DateTimeOffset.Parse("1/9/2009 5:15:20 PM +00:00", CultureInfo.InvariantCulture);

            Assert.AreEqual(expectedLogonTime, Truncate(logonInfo.LogonTime));

            var expectedLogoffTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLogoffTime, (DateTimeOffset)logonInfo.LogoffTime);

            var expectedKickOffTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedKickOffTime, (DateTimeOffset)logonInfo.KickOffTime);

            var expectedPwdLastChangeTime = DateTimeOffset.Parse("1/7/2009 2:33:58 PM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdLastChangeTime, Truncate(logonInfo.PwdLastChangeTime));

            var expectedPwdCanChangeTime = DateTimeOffset.Parse("1/8/2009 2:33:58 PM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdCanChangeTime, Truncate(logonInfo.PwdCanChangeTime));

            var expectedPwdMustChangeTime = DateTimeOffset.Parse("1/1/0001 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedPwdMustChangeTime, (DateTimeOffset)logonInfo.PwdMustChangeTime);

            Assert.AreEqual(46, logonInfo.LogonCount);
            Assert.AreEqual(0, logonInfo.BadPasswordCount);
            Assert.AreEqual(UserFlags.LOGON_EXTRA_SIDS, logonInfo.UserFlags);

            Assert.AreEqual(
                UserAccountControlFlags.ADS_UF_LOCKOUT | UserAccountControlFlags.ADS_UF_NORMAL_ACCOUNT,
                logonInfo.UserAccountControl
            );

            Assert.AreEqual(0, logonInfo.SubAuthStatus);

            var expectedLastSuccessfulILogon = DateTimeOffset.Parse("1/1/1601 12:00:00 AM +00:00", CultureInfo.InvariantCulture);
            Assert.AreEqual(expectedLastSuccessfulILogon, (DateTimeOffset)logonInfo.LastSuccessfulILogon);

            var expectedLastLastFailedILogon = DateTimeOffset.Parse("1/1/1601 12:00:00 AM +00:00", CultureInfo.InvariantCulture);

            Assert.AreEqual(expectedLastLastFailedILogon, (DateTimeOffset)logonInfo.LastFailedILogon);
            Assert.AreEqual("user.test", logonInfo.UserName.ToString());
            Assert.AreEqual("User Test", logonInfo.UserDisplayName.ToString());
            Assert.AreEqual("", logonInfo.LogonScript.ToString());
            Assert.AreEqual("", logonInfo.ProfilePath.ToString());
            Assert.AreEqual("", logonInfo.HomeDirectory.ToString());
            Assert.AreEqual("", logonInfo.HomeDrive.ToString());
            Assert.AreEqual("WS2008\0", logonInfo.ServerName.ToString());
            Assert.AreEqual("DOMAIN\0", logonInfo.DomainName.ToString());
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075", logonInfo.DomainSid.Value);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075-1106", logonInfo.UserSid.Value);
            Assert.AreEqual("S-1-5-21-4028881986-3284141023-698984075-513", logonInfo.GroupSid.Value);
            Assert.AreEqual(11, logonInfo.GroupSids.Count());
            Assert.AreEqual(7, logonInfo.ExtraSids.Count());

            Assert.IsNull(logonInfo.ResourceDomainSid);
            Assert.IsNotNull(logonInfo.ResourceGroups);
            Assert.AreEqual(0, logonInfo.ResourceGroups.Count());
        }

        [TestMethod]
        public async Task ClientInfo()
        {
            var cert = await GeneratePac();

            Assert.IsNotNull(cert.ClientInformation);

            Assert.AreEqual("user.test", cert.ClientInformation.Name);
            Assert.AreEqual((DateTimeOffset)cert.ClientInformation.ClientId, DateTimeOffset.Parse("1/9/2009 5:19:50 PM +00:00", CultureInfo.InvariantCulture));
        }

        [TestMethod]
        public async Task UpnDomainInfo()
        {
            var cert = await GeneratePac();

            Assert.IsNotNull(cert.UpnDomainInformation);

            Assert.AreEqual("DOMAIN.COM", cert.UpnDomainInformation.Domain);
            Assert.AreEqual("user.test@domain.com", cert.UpnDomainInformation.Upn);
            Assert.AreEqual((UpnDomainFlags)0, cert.UpnDomainInformation.Flags);
        }

        [TestMethod]
        public async Task PacGenerationRoundtrip()
        {
            var realmService = new FakeRealmService("foo.com");
            var krbtgt = await realmService.Principals.RetrieveKrbtgt();
            var key = await krbtgt.RetrieveLongTermCredential();

            var user = await realmService.Principals.Find("user@foo.com");

            var pac = await user.GeneratePac();

            Assert.IsNotNull(pac);

            var encoded = pac.Encode(key, key);

            var decoded = new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = encoded });

            Assert.IsNotNull(decoded.LogonInfo);
        }

        private static async Task<PrivilegedAttributeCertificate> GeneratePac()
        {
            var data = ReadDataFile("rc4-kerberos-data");
            var key = ReadDataFile("rc4-key-data");

            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = DefaultActions };

            var result = await validator.Validate(data);

            var pac = result.Ticket.AuthorizationData
                .Where(d => d.Type == AuthorizationDataType.AdIfRelevant)
                .Select(d => d.DecodeAdIfRelevant()
                    .Where(a => a.Type == AuthorizationDataType.AdWin2kPac)
                ).First();

            return new PrivilegedAttributeCertificate(new KrbAuthorizationData { Type = AuthorizationDataType.AdWin2kPac, Data = pac.First().Data });
        }

        private static DateTimeOffset Truncate(DateTimeOffset dateTime)
        {
            if (dateTime == DateTimeOffset.MinValue || dateTime == DateTimeOffset.MaxValue)
            {
                return dateTime;
            }

            return dateTime.AddTicks(-(dateTime.Ticks % TimeSpan.FromSeconds(1).Ticks));
        }
    }
}
