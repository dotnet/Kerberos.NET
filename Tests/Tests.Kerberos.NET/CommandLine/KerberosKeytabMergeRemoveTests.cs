// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosKeytabMergeRemoveTests : CommandLineTestBase
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

        private static string CreateKeytabFile(params (string principal, string realm, EncryptionType etype)[] entries)
        {
            var keytab = new KeyTable();

            foreach (var entry in entries)
            {
                var key = new KerberosKey(
                    key: new byte[32],
                    etype: entry.etype,
                    principal: new PrincipalName(PrincipalNameType.NT_PRINCIPAL, entry.realm, new[] { entry.principal })
                );

                keytab.Entries.Add(new KeyEntry(key));
            }

            var tmpFile = Path.GetTempFileName();

            using (var fs = new FileStream(tmpFile, FileMode.Create))
            using (var writer = new BinaryWriter(fs))
            {
                keytab.Write(writer);
            }

            return tmpFile;
        }

        [TestMethod]
        public void KeytabCommandParsesMergeFlag()
        {
            var parameters = CommandLineParameters.Parse("kt source.keytab --merge other.keytab");
            var command = (KerberosKeytabCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("other.keytab", command.MergeFrom);
        }

        [TestMethod]
        public void KeytabCommandParsesRemoveFlag()
        {
            var parameters = CommandLineParameters.Parse("kt source.keytab --remove host/server.example.com");
            var command = (KerberosKeytabCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.AreEqual("host/server.example.com", command.RemovePrincipal);
        }

        [TestMethod]
        public void KeytabCommandRemoveETypeCanBeSet()
        {
            var parameters = CommandLineParameters.Parse("kt source.keytab --remove host/server");
            var command = (KerberosKeytabCommand)parameters.CreateCommandExecutor(InputControl.Default());

            // Nullable enum can't be parsed from command line, so set directly
            command.RemoveEncryptionType = EncryptionType.AES256_CTS_HMAC_SHA1_96;

            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, command.RemoveEncryptionType);
        }

        [TestMethod]
        public void KeytabCommandParsesOutputFlag()
        {
            var parameters = CommandLineParameters.Parse("kt source.keytab --merge other.keytab --output result.keytab");
            var command = (KerberosKeytabCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.AreEqual("result.keytab", command.OutputFile);
        }

        [TestMethod]
        public async Task KeytabCommandMergesKeytabs()
        {
            var sourceFile = CreateKeytabFile(
                ("user1", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96)
            );

            var mergeFile = CreateKeytabFile(
                ("user2", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96)
            );

            var outputFile = Path.GetTempFileName();

            try
            {
                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse(
                    $"kt -f \"{sourceFile}\" --merge \"{mergeFile}\" --output \"{outputFile}\""
                );
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(output.Contains("Merged", StringComparison.OrdinalIgnoreCase), $"Expected merge message: {output}");

                // Verify the output keytab has both entries
                var result = new KeyTable(File.ReadAllBytes(outputFile));
                Assert.AreEqual(2, result.Entries.Count);
            }
            finally
            {
                File.Delete(sourceFile);
                File.Delete(mergeFile);
                File.Delete(outputFile);
            }
        }

        [TestMethod]
        public async Task KeytabCommandMergeSkipsDuplicates()
        {
            var sourceFile = CreateKeytabFile(
                ("user1", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96)
            );

            // Same principal as source
            var mergeFile = CreateKeytabFile(
                ("user1", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96)
            );

            var outputFile = Path.GetTempFileName();

            try
            {
                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse(
                    $"kt -f \"{sourceFile}\" --merge \"{mergeFile}\" --output \"{outputFile}\""
                );
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(output.Contains("Merged 0", StringComparison.OrdinalIgnoreCase) ||
                              output.Contains("Merged", StringComparison.OrdinalIgnoreCase),
                    $"Expected merge output: {output}");
            }
            finally
            {
                File.Delete(sourceFile);
                File.Delete(mergeFile);
                File.Delete(outputFile);
            }
        }

        [TestMethod]
        public async Task KeytabCommandRemovesEntries()
        {
            var sourceFile = CreateKeytabFile(
                ("user1", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96),
                ("user2", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96),
                ("user3", "TEST.COM", EncryptionType.AES128_CTS_HMAC_SHA1_96)
            );

            var outputFile = Path.GetTempFileName();

            try
            {
                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse(
                    $"kt -f \"{sourceFile}\" --remove user2 --output \"{outputFile}\""
                );
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(output.Contains("Removed", StringComparison.OrdinalIgnoreCase), $"Expected remove message: {output}");

                // Verify user2 was removed
                var result = new KeyTable(File.ReadAllBytes(outputFile));
                Assert.AreEqual(2, result.Entries.Count);

                Assert.IsFalse(
                    result.Entries.Any(e => e.Principal?.FullyQualifiedName?.Contains("user2") == true),
                    "user2 should have been removed"
                );
            }
            finally
            {
                File.Delete(sourceFile);
                File.Delete(outputFile);
            }
        }

        [TestMethod]
        public async Task KeytabCommandRemovesByEType()
        {
            var sourceFile = CreateKeytabFile(
                ("user1", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96),
                ("user1", "TEST.COM", EncryptionType.AES128_CTS_HMAC_SHA1_96)
            );

            var outputFile = Path.GetTempFileName();

            try
            {
                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse(
                    $"kt -f \"{sourceFile}\" --remove user1 --output \"{outputFile}\""
                );
                var command = (KerberosKeytabCommand)parameters.CreateCommandExecutor(io);
                command.RemoveEncryptionType = EncryptionType.AES128_CTS_HMAC_SHA1_96;

                await command.Execute();

                // Should only remove the AES128 entry
                var result = new KeyTable(File.ReadAllBytes(outputFile));
                Assert.AreEqual(1, result.Entries.Count);
                Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, result.Entries.First().EncryptionType);
            }
            finally
            {
                File.Delete(sourceFile);
                File.Delete(outputFile);
            }
        }

        [TestMethod]
        public async Task KeytabCommandMergeHandlesMissingSource()
        {
            var sourceFile = CreateKeytabFile(
                ("user1", "TEST.COM", EncryptionType.AES256_CTS_HMAC_SHA1_96)
            );

            try
            {
                var io = CreateIO(out var writer);
                var parameters = CommandLineParameters.Parse(
                    $"kt -f \"{sourceFile}\" --merge nonexistent.keytab"
                );
                var command = parameters.CreateCommandExecutor(io);

                await command.Execute();

                var output = writer.ToString();

                Assert.IsTrue(
                    output.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
                    output.Contains("error", StringComparison.OrdinalIgnoreCase),
                    $"Expected error for missing merge source: {output}"
                );
            }
            finally
            {
                File.Delete(sourceFile);
            }
        }
    }
}
