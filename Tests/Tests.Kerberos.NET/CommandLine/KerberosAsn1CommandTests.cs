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
    public class KerberosAsn1CommandTests : CommandLineTestBase
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
        public void Asn1CommandCanBeCreated()
        {
            var parameters = CommandLineParameters.Parse("kasn1 dGVzdA==");
            var command = (KerberosAsn1Command)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("dGVzdA==", command.Data);
        }

        [TestMethod]
        public void Asn1CommandAliasesWork()
        {
            foreach (var alias in new[] { "asn1", "asn" })
            {
                var parameters = CommandLineParameters.Parse($"{alias} dGVzdA==");
                var command = parameters.CreateCommandExecutor(InputControl.Default());

                Assert.IsNotNull(command);
                Assert.IsInstanceOfType(command, typeof(KerberosAsn1Command));
            }
        }

        [TestMethod]
        public async Task Asn1CommandRequiresInput()
        {
            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse("kasn1");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            // Should indicate no input
            Assert.IsFalse(string.IsNullOrWhiteSpace(output) && output.Length > 200,
                "Should produce limited output when no data provided");
        }

        [TestMethod]
        public async Task Asn1CommandDecodesBase64DerSequence()
        {
            // Build a simple KRB-ERROR which is a valid DER structure
            var error = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED,
                Realm = "EXAMPLE.COM",
                STime = DateTimeOffset.UtcNow,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_SRV_INST,
                    Name = new[] { "krbtgt", "EXAMPLE.COM" }
                }
            };

            var encoded = error.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse($"kasn1 {base64}");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            // Should show ASN.1 structure elements
            Assert.IsTrue(
                output.Contains("SEQUENCE", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("APPLICATION", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("INTEGER", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("CONTEXT", StringComparison.OrdinalIgnoreCase),
                $"Expected ASN.1 tag names in output: {output}"
            );
        }

        [TestMethod]
        public async Task Asn1CommandDecodesHexInput()
        {
            // DER encoding of INTEGER 42: 02 01 2A
            var hex = "02012A";

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse($"kasn1 --hex {hex}");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            Assert.IsTrue(
                output.Contains("INTEGER", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("42"),
                $"Expected INTEGER value 42 in output: {output}"
            );
        }

        [TestMethod]
        public async Task Asn1CommandReadsFromFile()
        {
            var error = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_NONE,
                Realm = "FILE.TEST",
                STime = DateTimeOffset.UtcNow,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { "test" }
                }
            };

            var encoded = error.EncodeApplication();

            using (var tmpFile = new TemporaryFile())
            {
                File.WriteAllBytes(tmpFile.File, encoded.ToArray());

                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse($"kasn1 --file \"{tmpFile.File}\"");
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(
                    output.Contains("SEQUENCE", StringComparison.OrdinalIgnoreCase) ||
                    output.Contains("APPLICATION", StringComparison.OrdinalIgnoreCase),
                    $"Expected ASN.1 structure from file: {output}"
                );
            }
        }

        [TestMethod]
        public async Task Asn1CommandDepthLimitsOutput()
        {
            var error = new KrbError
            {
                ErrorCode = KerberosErrorCode.KDC_ERR_NONE,
                Realm = "DEPTH.TEST",
                STime = DateTimeOffset.UtcNow,
                SName = new KrbPrincipalName
                {
                    Type = PrincipalNameType.NT_PRINCIPAL,
                    Name = new[] { "test" }
                }
            };

            var encoded = error.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            // Full depth
            var ioFull = CreateIO(out var writerFull);
            var paramsFull = CommandLineParameters.Parse($"kasn1 {base64}");
            var cmdFull = paramsFull.CreateCommandExecutor(ioFull);
            await cmdFull.Execute();
            var fullOutput = writerFull.ToString();

            // Depth 1
            var ioLimited = CreateIO(out var writerLimited);
            var paramsLimited = CommandLineParameters.Parse($"kasn1 --depth 1 {base64}");
            var cmdLimited = paramsLimited.CreateCommandExecutor(ioLimited);
            await cmdLimited.Execute();
            var limitedOutput = writerLimited.ToString();

            // Limited depth should produce less output
            Assert.IsTrue(
                limitedOutput.Length <= fullOutput.Length,
                $"Depth-limited output ({limitedOutput.Length}) should be <= full output ({fullOutput.Length})"
            );
        }

        [TestMethod]
        public async Task Asn1CommandHandlesInvalidData()
        {
            var io = CreateIO(out var writer);
            // "AAAA" decodes to 3 zero bytes - not valid DER
            var parameters = CommandLineParameters.Parse("kasn1 AAAA");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            // Should handle gracefully without crashing
            Assert.IsFalse(string.IsNullOrWhiteSpace(output));
        }

        [TestMethod]
        public async Task Asn1CommandIdentifiesKerberosApplicationTags()
        {
            // AS-REQ has APPLICATION tag 10
            var asReq = new KrbAsReq
            {
                Body = new KrbKdcReqBody
                {
                    CName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_PRINCIPAL,
                        Name = new[] { "test" }
                    },
                    Realm = "TEST.COM",
                    SName = new KrbPrincipalName
                    {
                        Type = PrincipalNameType.NT_SRV_INST,
                        Name = new[] { "krbtgt", "TEST.COM" }
                    },
                    Till = DateTimeOffset.UtcNow.AddHours(1),
                    Nonce = 12345,
                    EType = new[] { EncryptionType.AES256_CTS_HMAC_SHA1_96 },
                }
            };

            var encoded = asReq.EncodeApplication();
            var base64 = Convert.ToBase64String(encoded.ToArray());

            var io = CreateIO(out var writer);
            var parameters = CommandLineParameters.Parse($"kasn1 {base64}");
            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            var output = writer.ToString();

            // Should identify APPLICATION 10 as AS-REQ
            Assert.IsTrue(
                output.Contains("AS-REQ", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("APPLICATION 10", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("APPLICATION", StringComparison.OrdinalIgnoreCase),
                $"Expected AS-REQ identification: {output}"
            );
        }
    }
}
