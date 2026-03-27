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
    public class KerberosFastCommandTests : CommandLineTestBase
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
        public void FastCommandCanBeCreated()
        {
            var parameters = CommandLineParameters.Parse("kfast EXAMPLE.COM");
            var command = (KerberosFastCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("EXAMPLE.COM", command.Realm);
        }

        [TestMethod]
        public void FastCommandAliasWorks()
        {
            var parameters = CommandLineParameters.Parse("fast TEST.COM");
            var command = parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsInstanceOfType(command, typeof(KerberosFastCommand));
        }

        [TestMethod]
        public void FastCommandParsesTestCf2Flag()
        {
            var parameters = CommandLineParameters.Parse("kfast --test-cf2");
            var command = (KerberosFastCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.TestCf2);
        }

        [TestMethod]
        public void FastCommandParsesProbeFlag()
        {
            var parameters = CommandLineParameters.Parse("kfast --probe EXAMPLE.COM");
            var command = (KerberosFastCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Probe);
        }

        [TestMethod]
        public void FastCommandParsesVerboseFlag()
        {
            var parameters = CommandLineParameters.Parse("kfast --verbose EXAMPLE.COM");
            var command = (KerberosFastCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Verbose);
        }

        [TestMethod]
        public async Task FastCommandCf2TestProducesOutput()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kfast --test-cf2");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("CF2", StringComparison.OrdinalIgnoreCase),
                $"Expected CF2 test output: {output}"
            );
        }

        [TestMethod]
        public async Task FastCommandCf2TestShowsKeys()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kfast --test-cf2");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("Key1", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Key2", StringComparison.OrdinalIgnoreCase),
                $"Expected key display: {output}"
            );

            Assert.IsTrue(
                output.Contains("Result", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("completed", StringComparison.OrdinalIgnoreCase),
                $"Expected completion message: {output}"
            );
        }

        [TestMethod]
        public async Task FastCommandCf2TestShowsEncryptionType()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kfast --test-cf2");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("AES128", StringComparison.OrdinalIgnoreCase),
                $"Expected AES128 encryption type: {output}"
            );
        }

        [TestMethod]
        public async Task FastCommandCf2ProducesDeterministicResult()
        {
            var io1 = CreateIO(out var writer1);
            var params1 = CommandLineParameters.Parse("kfast --test-cf2");
            var cmd1 = params1.CreateCommandExecutor(io1);
            await cmd1.Execute();

            var io2 = CreateIO(out var writer2);
            var params2 = CommandLineParameters.Parse("kfast --test-cf2");
            var cmd2 = params2.CreateCommandExecutor(io2);
            await cmd2.Execute();

            // Same inputs should produce same CF2 result
            Assert.AreEqual(writer1.ToString(), writer2.ToString());
        }
    }
}
