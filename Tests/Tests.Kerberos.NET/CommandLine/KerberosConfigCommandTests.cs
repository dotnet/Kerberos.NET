﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Kerberos.NET.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosConfigCommandTests : CommandLineTestBase
    {
        [TestMethod]
        public async Task ConfigSetsValue()
        {
            using (var tmpConfigFile = new TemporaryFile())
            {
                var config = Krb5Config.Parse(File.ReadAllText(tmpConfigFile.File));
                Assert.IsFalse(config.Defaults.AllowWeakCrypto);

                string commandLine = $"kconfig --config \"{tmpConfigFile.File}\" libdefaults.allow_weak_crypto=true";

                config = await ExecuteCommand(commandLine, tmpConfigFile.File);

                Assert.IsTrue(config.Defaults.AllowWeakCrypto);
            }
        }

        [TestMethod]
        public async Task ConfigAppendsValue()
        {
            using (var tmpConfigFile = new TemporaryFile())
            {
                var config = Krb5Config.Parse(File.ReadAllText(tmpConfigFile.File));
                Assert.IsFalse(config.Defaults.AllowWeakCrypto);

                string commandLine = $"kconfig --config \"{tmpConfigFile.File}\" realms.\"example.com\".kdc=foo.com";

                config = await ExecuteCommand(commandLine, tmpConfigFile.File);

                Assert.AreEqual(1, config.Realms["example.com"].Kdc.Count);
                Assert.AreEqual("foo.com", config.Realms["example.com"].Kdc.First());

                commandLine = $"kconfig --config \"{tmpConfigFile.File}\" +realms.\"example.com\".kdc=bar.com";

                config = await ExecuteCommand(commandLine, tmpConfigFile.File);

                Assert.AreEqual(2, config.Realms["example.com"].Kdc.Count);
                Assert.AreEqual("foo.com", config.Realms["example.com"].Kdc.First());
                Assert.AreEqual("bar.com", config.Realms["example.com"].Kdc.ElementAt(1));
            }
        }


        [TestMethod]
        public async Task ConfigRemovesValue()
        {
            using (var tmpConfigFile = new TemporaryFile())
            {
                var config = Krb5Config.Parse(File.ReadAllText(tmpConfigFile.File));
                Assert.IsFalse(config.Defaults.AllowWeakCrypto);

                string commandLine = $"kconfig --config \"{tmpConfigFile.File}\" realms.\"example.com\".kdc=foo.com";

                config = await ExecuteCommand(commandLine, tmpConfigFile.File);

                Assert.AreEqual(1, config.Realms["example.com"].Kdc.Count);
                Assert.AreEqual("foo.com", config.Realms["example.com"].Kdc.First());

                commandLine = $"kconfig --config \"{tmpConfigFile.File}\" +realms.\"example.com\".kdc=";

                config = await ExecuteCommand(commandLine, tmpConfigFile.File);

                Assert.AreEqual(0, config.Realms["example.com"].Kdc.Count);
            }
        }

        private static async Task<Krb5Config> ExecuteCommand(string commandLine, string tmpCacheFile)
        {
            var io = new InputControl
            {
                Clear = () => { },
                HookCtrlC = hook => { },
                ResetColor = () => { },
                SetColor = c => { },
                Writer = new StringWriter()
            };

            var parameters = CommandLineParameters.Parse(commandLine);

            var command = (KerberosConfigCommand)parameters.CreateCommandExecutor(io);

            await command.Execute();

            return Krb5Config.Parse(File.ReadAllText(tmpCacheFile));
        }
    }
}
