// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Kerberos.NET.CommandLine;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class CommandLineTests
    {
        private const string KInitParameters = "kinit -f -C -V -t foo.key -c \"foo\\bar\\baz.cache\"";

        [TestMethod]
        public void CommandLineParser()
        {
            var parameters = CommandLineParameters.Parse(KInitParameters);

            Assert.IsNotNull(parameters);
            Assert.AreEqual("kinit", parameters.Command);
            Assert.AreEqual(7, parameters.Parameters.Length);
            Assert.AreEqual("-f", parameters.Parameters[0]);
            Assert.AreEqual("-C", parameters.Parameters[1]);
            Assert.AreEqual("-V", parameters.Parameters[2]);
            Assert.AreEqual("-t", parameters.Parameters[3]);
            Assert.AreEqual("foo.key", parameters.Parameters[4]);
            Assert.AreEqual("-c", parameters.Parameters[5]);
            Assert.AreEqual("foo\\bar\\baz.cache", parameters.Parameters[6]);
        }

        [TestMethod]
        public void ParserGeneratesCommand()
        {
            var parameters = CommandLineParameters.Parse(KInitParameters);

            var command = parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.IsInstanceOfType(command, typeof(KerberosInitCommand));
        }

        [TestMethod]
        public void CommandProcessesParameters()
        {
            var parameters = CommandLineParameters.Parse(KInitParameters);

            var command = (KerberosInitCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.AreEqual("foo\\bar\\baz.cache", command.Cache);
            Assert.AreEqual("foo.key", command.Keytab);

            Assert.IsTrue(command.Verbose);
            Assert.IsTrue(command.Forward.Value);
            Assert.IsTrue(command.Canonicalize.Value);
            Assert.IsNull(command.Proxy);
        }

        [TestMethod]
        public void CommandDisplaysHelp()
        {
            var parameters = CommandLineParameters.Parse(KInitParameters);

            var io = InputControl.Default();

            var textWriter = new StringWriter();

            io.Writer = textWriter;

            var command = parameters.CreateCommandExecutor(io);

            command.DisplayHelp();

            textWriter.Flush();
            var str = textWriter.ToString();

            Assert.IsTrue(str.StartsWith("Usage: kinit principal", System.StringComparison.OrdinalIgnoreCase));
        }

        [TestMethod]
        public async Task CommandLineHelpCommand()
        {
            var parameters = CommandLineParameters.Parse("help");

            var io = InputControl.Default();

            var textWriter = new StringWriter();

            io.Writer = textWriter;

            var command = parameters.CreateCommandExecutor(io);

            await command.Execute();

            textWriter.Flush();
            var str = textWriter.ToString();

            foreach (var result in new[] { "help", "kconfig", "kdestroy", "kinit", "klist" })
            {
                Assert.IsTrue(str.Contains(result));
            }
        }

        [TestMethod]
        public void AllCommandsFound()
        {
            var types = LoadTypes();
            var io = InputControl.Default();

            Assert.AreEqual(5, types.Count());

            foreach (var type in types)
            {
                var attr = type.GetCustomAttribute<CommandLineCommandAttribute>();

                Assert.IsNotNull(attr);

                Assert.IsNotNull(attr.Command);
                Assert.IsNotNull(attr.Description);

                var commandLine = CommandLineParameters.Parse(attr.Command);

                Assert.IsNotNull(commandLine);

                io.Writer = new StringWriter();

                var command = commandLine.CreateCommandExecutor(io);
                Assert.IsNotNull(command);

                command.DisplayHelp();

                Assert.IsTrue(!string.IsNullOrWhiteSpace(io.Writer.ToString()));
                Assert.IsTrue(io.Writer.ToString().Contains(attr.Command));
            }
        }

        internal static IEnumerable<Type> LoadTypes()
        {
            var types = typeof(BaseCommand).Assembly.GetTypes().Where(t => t.GetCustomAttribute<CommandLineCommandAttribute>() != null);

            foreach (var type in types)
            {
                yield return type;
            }
        }
    }
}
