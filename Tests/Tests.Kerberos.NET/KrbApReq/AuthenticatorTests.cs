using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AuthenticatorTests : BaseTest
    {
        private const string ApReqWithoutPacLogonInfo = "boIDTDCCA0igAwIBBaEDAgEOogcDBQAgAAAAo4ICN2GCAjMwggIvoAMCAQWhHxsdQ09SUC5JREVOVElUWUlOVEVSVkVOVElPTi5DT02iWDBWoAMCAQKhTz" + "BNGyxob3N0L2Rvd25sZXZlbC5jb3JwLmlkZW50aXR5aW50ZXJ2ZW50aW9uLmNvbRsdQ09SUC5JREVOVElUWUlOVEVSVkVOVElPTi5DT02jggGrMIIBp6ADAgESooIBngSCAZqAOMK78AL7VMUY05BE51mLKAYYWwIicv" +
            "kQj8XEg7GMGhxNqDtmcEOwTbAARjW0HU8gnOHs69xOwCJKC0PWXoO3pG7MrXL1jWke5VxpRy8cfAyNtMAmw2+UgxR72C7ypROT7TaJnubNr/2Rm6M9a/Ahd3HHb1TUa4WYpnDYnzjJsVKA6+FZMEG4OXuMtq89j8mK" +
            "sLPlMeuIpw5afr+3Td9Js/hnR5DhkN1ePlIQtW++POYlVENpWn/qDy6fDyNjmeh/ctUJK32aE6yrQb4ONo37J+PETLeB5kDWmx6qS1sjdXODQCMgixD+2+pC+uvYTqOtcK4KBikaQbShT/UaEwBwr6JLuZ4sg+f9lV" +
            "SwaZ5DR9zvcd6MK3/M85y3huzmKrlv/nwTcn6Q6Psh6s7KRfM28Q3aCn52njFomk9hlQBZMqoiHCwQijXeiI8MnHtYSyq79DKJHkYG9B/nwkY+4ZpD72fAxiA19uidl2TyEGhT1t0hn+Vn/IpND64DPBOS5x33qXw/" +
            "uf8lmT8jrpH9rspN+VtyNzUsryAeBKSB9zCB9KADAgESooHsBIHpB4XGJsImULSllCH6s+tXNu/SF2LzfAk2YQsxn2crw3tNzGpGqJX/ilfLgEsugPrt+p45yLd6yvu56IpPI/KZ4BKQDcjRmyCRj+RA7SlrEV+pvU" +
            "vHbjMfqkMS2VujYh/7fidiBB+st3gYxfL3rzrytj5bqVSnXzhfLnMV/ewtaGzFNwDOUMR/kAHbJMKS+2pT3+K1B17gquN+vFPdGDEk9D7OmaeUL0bNnBxR/uyjfL9fXdOetS0Ri7TIuy89sOwkGzG7tVHkisDYyjFW" +
            "yrQxaW4pHerPIOncMt0wd7pLr1gabCayo+94ajo=";

        [TestMethod]
        public async Task AuthenticatorGetsAsRep()
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
        }

        [TestMethod]
        public async Task Authenticator_DownLevelNameFormat()
        {
            var authenticator = new KerberosAuthenticator(
                new KerberosValidator(new KeyTable(ReadDataFile("sample.keytab")))
                {
                    ValidateAfterDecrypt = DefaultActions
                });

            authenticator.UserNameFormat = UserNameFormat.DownLevelLogonName;
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
                        "CORP.IDENTITYINTERVENTION.com",
                        new[] { "host/downlevel.corp.identityintervention.com" }
                    ),
                    saltType: SaltType.ActiveDirectoryUser
                )
            );

            var authenticator = new KerberosAuthenticator(new KerberosValidator(key) { ValidateAfterDecrypt = DefaultActions });

            var result = await authenticator.Authenticate(data);

            Assert.IsNotNull(result);

            Assert.AreEqual(1, result.Claims.Count());

            Assert.AreEqual("administrator/CORP.IDENTITYINTERVENTION.COM/CORP.IDENTITYINTERVENTION.COM", result.Name);
        }
    }
}
