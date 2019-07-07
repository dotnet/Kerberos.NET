using Kerberos.NET.Credentials;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET.Credentials
{
    [TestClass]
    public class KerberosPasswordTests
    {
        [TestMethod]
        public void TestParsePasswordCredential()
        {
            var cred = new KerberosPasswordCredential("username", "password", "domain.com");

            Assert.AreEqual("username", cred.UserName);
            Assert.AreEqual("DOMAIN.COM", cred.Domain);
        }

        [TestMethod]
        public void TestParsePasswordCredentialWithDomainInUser()
        {
            var cred = new KerberosPasswordCredential("username@domain.com", "password");

            Assert.AreEqual("username", cred.UserName);
            Assert.AreEqual("DOMAIN.COM", cred.Domain);
        }

        [TestMethod]
        public void TestParsePasswordCredentialWithDomainInUserAndDomainParam()
        {
            var cred = new KerberosPasswordCredential("username@domain.com", "password", "domain2.com");

            Assert.AreEqual("username", cred.UserName);
            Assert.AreEqual("DOMAIN2.COM", cred.Domain);
        }
    }
}
