// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosTokenDecodeCommandTests : CommandLineTestBase
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
        public void TokenCommandCanBeCreated()
        {
            var parameters = CommandLineParameters.Parse("ktoken foobar");
            var command = (KerberosTokenDecodeCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("foobar", command.Token);
        }

        [TestMethod]
        public void TokenCommandAliasWorks()
        {
            var parameters = CommandLineParameters.Parse("token foobar");
            var command = parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsInstanceOfType(command, typeof(KerberosTokenDecodeCommand));
        }

        [TestMethod]
        public async Task TokenCommandRequiresInput()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("ktoken");
            var command = parameters.CreateCommandExecutor(io);

            var result = await command.Execute();

            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task TokenCommandDecodesNegotiateHeader()
        {
            // BaseTest.RC4Header starts with "Negotiate " prefix; extract just the base64 part
            var token = BaseTest.RC4Header.Replace("Negotiate ", "").Trim();

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("ktoken placeholder");
            var command = (KerberosTokenDecodeCommand)parameters.CreateCommandExecutor(io);
            command.Token = token;

            await command.Execute();

            var output = writer.ToString();

            // Should detect it's a SPNEGO/negotiate token
            Assert.IsTrue(
                output.Contains("SPNEGO", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Negotiate", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("AP-REQ", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Mechanism", StringComparison.OrdinalIgnoreCase),
                $"Expected token type identification in output: {output}"
            );
        }

        [TestMethod]
        public async Task TokenCommandStripsNegotiatePrefix()
        {
            // RC4Header already has "Negotiate " prefix - pass it directly to the command
            // to verify the prefix-stripping logic works
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("ktoken placeholder");
            var command = (KerberosTokenDecodeCommand)parameters.CreateCommandExecutor(io);
            command.Token = BaseTest.RC4Header;

            await command.Execute();

            var output = writer.ToString();

            // Should still work after stripping the Negotiate prefix
            Assert.IsFalse(string.IsNullOrWhiteSpace(output));
            Assert.IsFalse(output.Contains("not valid base64", StringComparison.OrdinalIgnoreCase));
        }

        [TestMethod]
        public async Task TokenCommandHandlesInvalidBase64()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("ktoken not-valid-base64!!!");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsFalse(string.IsNullOrWhiteSpace(output));
        }

        [TestMethod]
        public async Task TokenCommandVerboseFlag()
        {
            var parameters = CommandLineParameters.Parse("ktoken --verbose foobar");
            var command = (KerberosTokenDecodeCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Verbose);
        }

        [TestMethod]
        public async Task TokenCommandRawFlag()
        {
            var parameters = CommandLineParameters.Parse("ktoken --raw foobar");
            var command = (KerberosTokenDecodeCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsTrue(command.Raw);
        }

        [TestMethod]
        public async Task TokenCommandDecodesKrbError()
        {
            // Create a minimal KRB-ERROR and encode it
            var error = new KrbError
            {
                ErrorCode = KerberosErrorCode.KRB_AP_ERR_TKT_EXPIRED,
                Realm = "TEST.REALM",
                EText = "Ticket expired",
                STime = DateTimeOffset.UtcNow,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { "krbtgt", "TEST.REALM" }
                }
            };

            var encoded = error.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse($"ktoken {base64}");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("KRB-ERROR", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("TEST.REALM", StringComparison.OrdinalIgnoreCase),
                $"Expected KRB-ERROR details in output: {output}"
            );
        }
    }
}
