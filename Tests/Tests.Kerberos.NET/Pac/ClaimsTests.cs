using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{

    [TestClass]
    public class ClaimsTests : BaseTest
    {
        [TestMethod]
        public async Task TestParseClaims()
        {
            var validator = new KerberosValidator(new KeyTable(ReadDataFile("sample.keytab"))) { ValidateAfterDecrypt = DefaultActions };

            var authenticator = new KerberosAuthenticator(validator);

            var result = await authenticator.Authenticate(RC4Ticket_Claims);

            Assert.IsNotNull(result);

            Assert.IsTrue(result.Claims.Count() > 0);

            Assert.IsTrue(result.Claims.Any(c => c.Type == "ad://ext/employeeType:88d4d68c56082042" && c.Value == "lazy"));

            Assert.AreEqual(2, result.Claims.Count(c => c.Type == "ad://ext/localeID:88d4d68c6aa51687"));
        }

        [TestMethod]
        public async Task TestValidatorClaimsPresent()
        {
            var validator = new KerberosValidator(new KeyTable(ReadDataFile("sample.keytab"))) { ValidateAfterDecrypt = DefaultActions };

            var authenticator = new KerberosAuthenticator(validator);

            var result = await authenticator.Authenticate(RC4Ticket_Claims);

            Assert.IsNotNull(result);

            var kerbIdentity = result as KerberosIdentity;

            Assert.IsNotNull(kerbIdentity);

            Assert.IsTrue(result.Claims.Count() > 0);

            Assert.IsFalse(result.Claims.Any(c => c.Type == "Validated"));

            Assert.AreEqual(DefaultActions, kerbIdentity.ValidationMode);
        }
    }
}
