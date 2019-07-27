using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AuthenticatorTests : BaseTest
    {
        [TestMethod]
        public async Task TestAuthenticatorGetsAsRep()
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
        public async Task TestAuthenticator_Default()
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
        public async Task TestAuthenticator_DownLevelNameFormat()
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
        public void TestMechTypes()
        {
            foreach (var mechType in KnownMechTypes)
            {
                Assert.IsFalse(string.IsNullOrWhiteSpace(MechType.LookupOid(mechType)));
            }
        }

        [TestMethod]
        public void TestUnknownMechType()
        {
            Assert.IsTrue(string.IsNullOrEmpty(MechType.LookupOid("1.2.3.4.5.6.7.8.9")));
        }
    }
}
