// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosCredCommandTests : CommandLineTestBase
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

        private static KrbCred CreateTestKrbCred()
        {
            var encKey = new KrbEncryptionKey
            {
                EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                Usage = KeyUsage.EncTgsRepPartSessionKey,
                KeyValue = new byte[32]
            };

            var ticket = new KrbTicket
            {
                Realm = "TEST.REALM",
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { "krbtgt", "TEST.REALM" }
                },
                EncryptedPart = new KrbEncryptedData
                {
                    EType = EncryptionType.AES256_CTS_HMAC_SHA1_96,
                    Cipher = new byte[64]
                }
            };

            var credInfo = new KrbCredInfo
            {
                Key = encKey,
                Realm = "TEST.REALM",
                PName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { "testuser" }
                },
                SName = ticket.SName,
                SRealm = "TEST.REALM",
                Flags = TicketFlags.Forwardable | TicketFlags.Renewable,
                AuthTime = DateTimeOffset.UtcNow.AddHours(-1),
                EndTime = DateTimeOffset.UtcNow.AddHours(8),
                StartTime = DateTimeOffset.UtcNow,
            };

            return KrbCred.WrapTicket(ticket, credInfo);
        }

        [TestMethod]
        public void CredCommandCanBeCreated()
        {
            var parameters = CommandLineParameters.Parse("kcred --decode foobar");
            var command = (KerberosCredCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("foobar", command.DecodeData);
        }

        [TestMethod]
        public void CredCommandAliasWorks()
        {
            var parameters = CommandLineParameters.Parse("cred --decode foobar");
            var command = parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsInstanceOfType(command, typeof(KerberosCredCommand));
        }

        [TestMethod]
        public async Task CredCommandDecodesBase64KrbCred()
        {
            var krbCred = CreateTestKrbCred();
            var encoded = krbCred.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse($"kcred --decode {base64}");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(output.Contains("KRB-CRED", StringComparison.OrdinalIgnoreCase), $"Expected KRB-CRED header: {output}");
            Assert.IsTrue(output.Contains("TEST.REALM", StringComparison.OrdinalIgnoreCase), $"Expected realm: {output}");
            Assert.IsTrue(output.Contains("Ticket", StringComparison.OrdinalIgnoreCase), $"Expected ticket info: {output}");
        }

        [TestMethod]
        public async Task CredCommandDecodesFromFile()
        {
            var krbCred = CreateTestKrbCred();
            var encoded = krbCred.EncodeApplication();

            using (var tmpFile = new TemporaryFile())
            {
                File.WriteAllBytes(tmpFile.File, encoded.ToArray());

                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse($"kcred --file \"{tmpFile.File}\"");
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(output.Contains("KRB-CRED", StringComparison.OrdinalIgnoreCase), $"Expected KRB-CRED: {output}");
                Assert.IsTrue(output.Contains("TEST.REALM", StringComparison.OrdinalIgnoreCase), $"Expected realm: {output}");
            }
        }

        [TestMethod]
        public async Task CredCommandDecodesBase64FileContent()
        {
            var krbCred = CreateTestKrbCred();
            var encoded = krbCred.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            using (var tmpFile = new TemporaryFile())
            {
                // Write base64 text to file (should auto-detect)
                File.WriteAllText(tmpFile.File, base64);

                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse($"kcred --file \"{tmpFile.File}\"");
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(output.Contains("KRB-CRED", StringComparison.OrdinalIgnoreCase), $"Expected KRB-CRED: {output}");
            }
        }

        [TestMethod]
        public async Task CredCommandShowsCredentialInfo()
        {
            var krbCred = CreateTestKrbCred();
            var encoded = krbCred.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse($"kcred --decode {base64}");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            // Should show the unencrypted credential info since EType is NULL
            Assert.IsTrue(
                output.Contains("testuser", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Credential Info", StringComparison.OrdinalIgnoreCase),
                $"Expected credential info details: {output}"
            );
        }

        [TestMethod]
        public async Task CredCommandHandlesInvalidBase64()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kcred --decode not-valid-base64!!!");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("not valid base64", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Failed", StringComparison.OrdinalIgnoreCase),
                $"Expected error message: {output}"
            );
        }

        [TestMethod]
        public async Task CredCommandHandlesMissingFile()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kcred --file nonexistent_file.kirbi");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("error", StringComparison.OrdinalIgnoreCase),
                $"Expected file not found error: {output}"
            );
        }

        [TestMethod]
        public async Task CredCommandRequiresAction()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kcred");
            var command = parameters.CreateCommandExecutor(io);

            var result = await command.Execute();

            var output = writer.ToString();

            // Should prompt user that an action is needed
            Assert.IsFalse(string.IsNullOrWhiteSpace(output));
        }
    }
}
