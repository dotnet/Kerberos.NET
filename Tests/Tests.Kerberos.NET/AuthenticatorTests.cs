using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AuthenticatorTests : BaseTest
    {
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
    }
}
