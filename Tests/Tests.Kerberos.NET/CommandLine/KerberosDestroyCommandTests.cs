// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.IO;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosDestroyCommandTests : CommandLineTestBase
    {
        [TestMethod]
        public async Task DestroyExecutes()
        {
            using (var tmpCacheFile = new TemporaryFile())
            {
                var parameters = CommandLineParameters.Parse($"kdestroy --cache {tmpCacheFile.File}");

                var io = new InputControl
                {
                    Clear = () => { },
                    HookCtrlC = hook => { },
                    Writer = new StringWriter()
                };

                var command = (KerberosDestroyCommand)parameters.CreateCommandExecutor(io);

                Assert.IsNotNull(command);

                await command.Execute();

                var result = io.Writer.ToString();

                Assert.IsTrue(result.Contains("Cache file has been deleted."));

                var exists = File.Exists(tmpCacheFile.File);

                Assert.IsFalse(exists);
            }
        }
    }
}
