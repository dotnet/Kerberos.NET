// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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

            Assert.AreEqual("user@test.internal", principal.FullyQualifiedName);
            Assert.AreEqual(1, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_NoRealm_SrvInst()
        {
            var principal = KrbPrincipalName.FromString("host/test.internal", type: PrincipalNameType.NT_SRV_INST);

            Assert.AreEqual("host/test.internal", principal.FullyQualifiedName);
            Assert.AreEqual(2, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_SameRealm()
        {
            var principal = KrbPrincipalName.FromString(principal: "user@test.internal", realm: "test.internal");

            Assert.AreEqual("user@test.internal", principal.FullyQualifiedName);
            Assert.AreEqual(1, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_DifferentRealms()
        {
            var principal = KrbPrincipalName.FromString(principal: "user@test.internal", realm: "corp.test.internal");

            Assert.AreEqual("user@test.internal", principal.FullyQualifiedName);
            Assert.AreEqual(1, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_SrvInst()
        {
            var principal = KrbPrincipalName.FromString(principal: "krbtgt", type: PrincipalNameType.NT_SRV_INST, realm: "corp.test.internal");

            Assert.AreEqual("krbtgt/corp.test.internal", principal.FullyQualifiedName);
            Assert.AreEqual(2, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_X500()
        {
            var principal = KrbPrincipalName.FromString(principal: "CN=test,OU=blah,DC=corp,DC=test,DC=internal", type: PrincipalNameType.NT_X500_PRINCIPAL);

            Assert.AreEqual("CN=test,OU=blah,DC=corp,DC=test,DC=internal", principal.FullyQualifiedName);
            Assert.AreEqual(5, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_X500_IncludeDomain()
        {
            var principal = KrbPrincipalName.FromString(principal: "CN=test,OU=blah", type: PrincipalNameType.NT_X500_PRINCIPAL, realm: "corp.test.internal");

            Assert.AreEqual("CN=test,OU=blah,DC=corp,DC=test,DC=internal", principal.FullyQualifiedName);
            Assert.AreEqual(5, principal.Name.Length);
        }

        [TestMethod]
        public void PrincipalName_Empty()
        {
            var principal = KrbPrincipalName.FromString(principal: string.Empty);

            Assert.IsNotNull(principal);
            Assert.AreEqual(string.Empty, principal.FullyQualifiedName);
        }

        [TestMethod]
        public void PrincipalName_Equality_Matches()
        {
            var a = KrbPrincipalName.FromString("aaaa@bbbb.com");
            var b = KrbPrincipalName.FromString("aaaa@bbbb.com");

            Assert.IsTrue(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_DifferentNames()
        {
            var a = KrbPrincipalName.FromString("aaaa@bbbb.com");
            var b = KrbPrincipalName.FromString("bbbb@bbbb.com");

            Assert.IsFalse(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_Matches_DifferentNameTypes_Service()
        {
            var a = KrbPrincipalName.FromString("host/aaaa@bbbb.com", PrincipalNameType.NT_SRV_HST);
            var b = KrbPrincipalName.FromString("aaaa@bbbb.com", PrincipalNameType.NT_PRINCIPAL);

            Assert.IsFalse(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_DifferentNameTypes()
        {
            var a = KrbPrincipalName.FromString("aaaa@bbbb.com", PrincipalNameType.NT_PRINCIPAL);
            var b = KrbPrincipalName.FromString("aaaa@bbbb.com", PrincipalNameType.NT_SRV_HST);

            Assert.IsTrue(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_ServiceTypes()
        {
            var a = KrbPrincipalName.FromString("host/aaaa");
            var b = KrbPrincipalName.FromString("host/aaaa");

            Assert.IsTrue(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_ServiceTypes_WithRealm()
        {
            var a = KrbPrincipalName.FromString("host/aaaa@bbbb.com");
            var b = KrbPrincipalName.FromString("host/aaaa@bbbb.com");

            Assert.IsTrue(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_DifferentServiceTypes()
        {
            var a = KrbPrincipalName.FromString("aaaa/aaaa");
            var b = KrbPrincipalName.FromString("bbbb/aaaa");

            Assert.IsFalse(a.Matches(b));
        }

        [TestMethod]
        public void PrincipalName_Equality_ServiceTypeAliasesMatch()
        {
            var a = KrbPrincipalName.FromString("host/aaaa");
            var b = KrbPrincipalName.FromString("bbbb/aaaa");

            KrbPrincipalName.ServiceAliases["bbbb"] = "host";

            Assert.IsTrue(a.Matches(b));
        }
    }
}