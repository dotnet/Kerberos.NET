﻿using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AuthenticatorTests : BaseTest
    {
        private const string RC4Header = "Negotiate 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";

        [TestMethod]
        public async Task TestAuthenticator_Default()
        {
            var authenticator = new KerberosAuthenticator(new KerberosValidator(new KeyTable(File.ReadAllBytes("data\\sample.keytab"))) { ValidateAfterDecrypt = DefaultActions });

            Assert.IsNotNull(authenticator);

            var result = await authenticator.Authenticate(RC4Header);

            Assert.IsNotNull(result);

            Assert.AreEqual("Administrator@identityintervention.com", result.Name);
        }
        
        [TestMethod]
        public async Task TestAuthenticator_DownLevelNameFormat()
        {
            var authenticator = new KerberosAuthenticator(new KerberosValidator(new KeyTable(File.ReadAllBytes("data\\sample.keytab"))) { ValidateAfterDecrypt = DefaultActions });
            authenticator.UserNameFormat = UserNameFormat.DownLevelLogonName;
            var result = await authenticator.Authenticate(RC4Header);

            Assert.IsNotNull(result);
            Assert.AreEqual(@"IDENTITYINTER\Administrator", result.Name);
        }
    }
}
