// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.IO;
using Kerberos.NET.CommandLine;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosWhoAmIExtendedTests : CommandLineTestBase
    {
        [TestMethod]
        public void WhoAmIParsesSignaturesFlag()
        {
            var parameters = CommandLineParameters.Parse("whoami --signatures");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsTrue(command.Signatures);
        }

        [TestMethod]
        public void WhoAmIParsesDelegationFlag()
        {
            var parameters = CommandLineParameters.Parse("whoami --delegation");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsTrue(command.Delegation);
        }

        [TestMethod]
        public void WhoAmIParsesAllFlag()
        {
            var parameters = CommandLineParameters.Parse("whoami --all");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsTrue(command.All);
        }

        [TestMethod]
        public void WhoAmIParsesCombinedFlags()
        {
            var parameters = CommandLineParameters.Parse("whoami --logon --groups --claims --signatures --delegation");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Logon);
            Assert.IsTrue(command.Groups);
            Assert.IsTrue(command.Claims);
            Assert.IsTrue(command.Signatures);
            Assert.IsTrue(command.Delegation);
            Assert.IsFalse(command.All);
        }

        [TestMethod]
        public void WhoAmIParsesCache()
        {
            var parameters = CommandLineParameters.Parse("whoami --cache /tmp/krb5cc_test");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.AreEqual("/tmp/krb5cc_test", command.Cache);
        }

        [TestMethod]
        public void WhoAmIParsesVerbose()
        {
            var parameters = CommandLineParameters.Parse("whoami --verbose");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Verbose);
        }

        [TestMethod]
        public void WhoAmIDefaultFlagsAreOff()
        {
            var parameters = CommandLineParameters.Parse("whoami");
            var command = (KerberosWhoAmI)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsFalse(command.All);
            Assert.IsFalse(command.Logon);
            Assert.IsFalse(command.Groups);
            Assert.IsFalse(command.Claims);
            Assert.IsFalse(command.Signatures);
            Assert.IsFalse(command.Delegation);
        }
    }
}
