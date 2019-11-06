using Kerberos.NET.Credentials;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosPasswordTests
    {
        [TestMethod]
        public void ParsePasswordCredential()
        {
            var cred = new KerberosPasswordCredential("username", "password", "domain.com");

            Assert.AreEqual("username", cred.UserName);
            Assert.AreEqual("DOMAIN.COM", cred.Domain);
        }

        [TestMethod]
        public void ParsePasswordCredentialWithDomainInUser()
        {
            var cred = new KerberosPasswordCredential("username@domain.com", "password");

            Assert.AreEqual("username", cred.UserName);
            Assert.AreEqual("DOMAIN.COM", cred.Domain);
        }

        [TestMethod]
        public void ParsePasswordCredentialWithDomainInUserAndDomainParam()
        {
            var cred = new KerberosPasswordCredential("username@domain.com", "password", "domain2.com");

            Assert.AreEqual("username", cred.UserName);
            Assert.AreEqual("DOMAIN2.COM", cred.Domain);
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void Credential_MissingUserName()
        {
            var cred = new KerberosPasswordCredential("", "password", "domain2.com");

            cred.Validate();
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void Credential_MissingPassword()
        {
            var cred = new KerberosPasswordCredential("username@domain.com", "", "domain2.com");

            cred.Validate();
        }

        [TestMethod, ExpectedException(typeof(ArgumentException))]
        public void Credential_MissingDomain()
        {
            var cred = new KerberosPasswordCredential("username", "password", "");

            cred.Validate();
        }
    }
}
