using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class PrincipalNameTests
    {
        [TestMethod]
        public void PrincipalName_NoRealm()
        {
            var principal = KrbPrincipalName.FromString("user@test.internal");

            Assert.AreEqual(principal.FullyQualifiedName, "user@test.internal");
            Assert.AreEqual(1, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_NoRealm_SrvInst()
        {
            var principal = KrbPrincipalName.FromString("host/test.internal", type: PrincipalNameType.NT_SRV_INST);

            Assert.AreEqual(principal.FullyQualifiedName, "host/test.internal");
            Assert.AreEqual(2, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_SameRealm()
        {
            var principal = KrbPrincipalName.FromString(principal: "user@test.internal", realm: "test.internal");

            Assert.AreEqual(principal.FullyQualifiedName, "user@test.internal");
            Assert.AreEqual(1, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_DifferentRealms()
        {
            var principal = KrbPrincipalName.FromString(principal: "user@test.internal", realm: "corp.test.internal");

            Assert.AreEqual(principal.FullyQualifiedName, "user@test.internal");
            Assert.AreEqual(1, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_SrvInst()
        {
            var principal = KrbPrincipalName.FromString(principal: "krbtgt", type: PrincipalNameType.NT_SRV_INST, realm: "corp.test.internal");

            Assert.AreEqual(principal.FullyQualifiedName, "krbtgt/corp.test.internal");
            Assert.AreEqual(2, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_X500()
        {
            var principal = KrbPrincipalName.FromString(principal: "CN=test,OU=blah,DC=corp,DC=test,DC=internal", type: PrincipalNameType.NT_X500_PRINCIPAL);

            Assert.AreEqual(principal.FullyQualifiedName, "CN=test,OU=blah,DC=corp,DC=test,DC=internal");
            Assert.AreEqual(5, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_X500_IncludeDomain()
        {
            var principal = KrbPrincipalName.FromString(principal: "CN=test,OU=blah", type: PrincipalNameType.NT_X500_PRINCIPAL, realm: "corp.test.internal");

            Assert.AreEqual(principal.FullyQualifiedName, "CN=test,OU=blah,DC=corp,DC=test,DC=internal");
            Assert.AreEqual(5, principal.Name.Length);
        }
    }
}
