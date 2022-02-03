// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Kerberos.NET.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosInitCommandTests : CommandLineTestBase
    {
        private const string KInitParameters = "kinit --kdc {0} --cache {2} --realm corp.identityintervention.com --config {3} {1}";
        protected const string AdminAtCorpUserName = "administrator@corp.identityintervention.com";
        protected const string FakeAdminAtCorpPassword = "P@ssw0rd!";

        private static KerberosInitCommand CreateCommand(string kdc, string upn, string cache, string config, InputControl io)
        {
            var parameters = CommandLineParameters.Parse(string.Format(KInitParameters, kdc, upn, cache, config));

            return (KerberosInitCommand)parameters.CreateCommandExecutor(io);
        }

        [TestMethod]
        public async Task KinitExecutes()
        {
            var port = NextPort();
            using (var tmpCacheFile = new TemporaryFile())
            using (var tmpConfigFile = new TemporaryFile())
            {
                var config = Krb5Config.Default();

                File.WriteAllText(tmpConfigFile.File, config.Serialize());

                using (var listener = StartTcpListener(port))
                {
                    _ = listener.Start();

                    var reader = new CommandLineAutoReader();

                    var io = new InputControl
                    {
                        Clear = () => { },
                        HookCtrlC = hook => { },
                        ResetColor = () => { },
                        SetColor = c => { },
                        Reader = reader,
                        Writer = new StringWriter(),
                        ReadKey = () => ReadKey(reader)
                    };

                    var command = CreateCommand($"127.0.0.1:{port}", AdminAtCorpUserName, tmpCacheFile.File, tmpConfigFile.File, io);

                    reader.QueueNext(FakeAdminAtCorpPassword + "\n");

                    await command.Execute();

                    var output = io.Writer.ToString();

                    Assert.IsTrue(output.Contains("Ticket Count: 1"));
                    Assert.IsTrue(output.Contains("client : administrator", StringComparison.OrdinalIgnoreCase), output);
                }
            }
        }
    }
}
