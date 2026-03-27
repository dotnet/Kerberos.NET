// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosProxyCommandTests : CommandLineTestBase
    {
        private static InputControl CreateIO(out StringWriter writer)
        {
            writer = new StringWriter();

            return new InputControl
            {
                Clear = () => { },
                HookCtrlC = hook => { },
                ResetColor = () => { },
                SetColor = c => { },
                Writer = writer
            };
        }

        [TestMethod]
        public void ProxyCommandCanBeCreated()
        {
            var parameters = CommandLineParameters.Parse("kproxy EXAMPLE.COM");
            var command = (KerberosProxyCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("EXAMPLE.COM", command.Realm);
        }

        [TestMethod]
        public void ProxyCommandAliasWorks()
        {
            var parameters = CommandLineParameters.Parse("proxy TEST.COM");
            var command = parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsInstanceOfType(command, typeof(KerberosProxyCommand));
        }

        [TestMethod]
        public void ProxyCommandParsesUrl()
        {
            var parameters = CommandLineParameters.Parse("kproxy --url https://proxy.example.com/KdcProxy EXAMPLE.COM");
            var command = (KerberosProxyCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.AreEqual("https://proxy.example.com/KdcProxy", command.ProxyUrl);
            Assert.AreEqual("EXAMPLE.COM", command.Realm);
        }

        [TestMethod]
        public void ProxyCommandParsesVerbose()
        {
            var parameters = CommandLineParameters.Parse("kproxy --verbose EXAMPLE.COM");
            var command = (KerberosProxyCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Verbose);
        }

        [TestMethod]
        public async Task ProxyCommandOutputsHeader()
        {
            var io = CreateIO(out var writer);

            // Use a non-existent URL so it fails fast but we can verify output format
            var parameters = CommandLineParameters.Parse("kproxy --url https://127.0.0.1:1/KdcProxy TEST.REALM");
            var command = (KerberosProxyCommand)parameters.CreateCommandExecutor(io);
            command.Timeout = TimeSpan.FromSeconds(1);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("KDC Proxy", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Connectivity", StringComparison.OrdinalIgnoreCase),
                $"Expected connectivity test header: {output}"
            );
        }

        [TestMethod]
        public async Task ProxyCommandHandlesConnectionFailure()
        {
            var io = CreateIO(out var writer);

            var parameters = CommandLineParameters.Parse("kproxy --url https://127.0.0.1:1/KdcProxy NONEXISTENT.REALM");
            var command = (KerberosProxyCommand)parameters.CreateCommandExecutor(io);
            command.Timeout = TimeSpan.FromSeconds(1);

            await command.Execute();

            var output = writer.ToString();

            // Should report the error gracefully
            Assert.IsTrue(
                output.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("failed", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Time Elapsed", StringComparison.OrdinalIgnoreCase),
                $"Expected error report in output: {output}"
            );
        }

        [TestMethod]
        public async Task ProxyCommandDisplaysRealm()
        {
            var io = CreateIO(out var writer);

            var parameters = CommandLineParameters.Parse("kproxy --url https://127.0.0.1:1/KdcProxy MY.TEST.REALM");
            var command = (KerberosProxyCommand)parameters.CreateCommandExecutor(io);
            command.Timeout = TimeSpan.FromSeconds(1);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(output.Contains("MY.TEST.REALM"), $"Expected realm in output: {output}");
        }
    }
}
