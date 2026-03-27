// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.IO;
using System.Linq;
using Kerberos.NET.Client;
using Kerberos.NET.CommandLine;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class TransportSelectionTests : CommandLineTestBase
    {
        [TestMethod]
        public void KinitParsesTransportFlag()
        {
            var parameters = CommandLineParameters.Parse("kinit --transport tcp user@EXAMPLE.COM");
            var command = (KerberosInitCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("tcp", command.Transport);
        }

        [TestMethod]
        public void KlistParsesTransportFlag()
        {
            var parameters = CommandLineParameters.Parse("klist --transport https");
            var command = (KerberosListCommand)parameters.CreateCommandExecutor(InputControl.Default());

            Assert.IsNotNull(command);
            Assert.AreEqual("https", command.Transport);
        }

        [TestMethod]
        public void ConfigureTransportSelectsTcp()
        {
            using (var client = new KerberosClient())
            {
                KerberosInitCommand.ConfigureTransport(client, "tcp");

                foreach (var t in client.Transports)
                {
                    if (t is TcpKerberosTransport)
                    {
                        Assert.IsTrue(t.Enabled, "TCP should be enabled");
                    }
                    else
                    {
                        Assert.IsFalse(t.Enabled, $"{t.GetType().Name} should be disabled");
                    }
                }
            }
        }

        [TestMethod]
        public void ConfigureTransportSelectsUdp()
        {
            using (var client = new KerberosClient())
            {
                KerberosInitCommand.ConfigureTransport(client, "udp");

                foreach (var t in client.Transports)
                {
                    if (t is UdpKerberosTransport)
                    {
                        Assert.IsTrue(t.Enabled, "UDP should be enabled");
                    }
                    else
                    {
                        Assert.IsFalse(t.Enabled, $"{t.GetType().Name} should be disabled");
                    }
                }
            }
        }

        [TestMethod]
        public void ConfigureTransportSelectsHttps()
        {
            using (var client = new KerberosClient())
            {
                KerberosInitCommand.ConfigureTransport(client, "https");

                foreach (var t in client.Transports)
                {
                    if (t is HttpsKerberosTransport)
                    {
                        Assert.IsTrue(t.Enabled, "HTTPS should be enabled");
                    }
                    else
                    {
                        Assert.IsFalse(t.Enabled, $"{t.GetType().Name} should be disabled");
                    }
                }
            }
        }

        [TestMethod]
        public void ConfigureTransportProxyAliasSelectsHttps()
        {
            using (var client = new KerberosClient())
            {
                KerberosInitCommand.ConfigureTransport(client, "proxy");

                foreach (var t in client.Transports)
                {
                    if (t is HttpsKerberosTransport)
                    {
                        Assert.IsTrue(t.Enabled, "HTTPS should be enabled for 'proxy' alias");
                    }
                    else
                    {
                        Assert.IsFalse(t.Enabled, $"{t.GetType().Name} should be disabled");
                    }
                }
            }
        }

        [TestMethod]
        public void ConfigureTransportNullDoesNothing()
        {
            using (var client = new KerberosClient())
            {
                var beforeStates = client.Transports.Select(t => t.Enabled).ToArray();

                KerberosInitCommand.ConfigureTransport(client, null);

                var afterStates = client.Transports.Select(t => t.Enabled).ToArray();

                CollectionAssert.AreEqual(beforeStates, afterStates);
            }
        }

        [TestMethod]
        public void ConfigureTransportEmptyDoesNothing()
        {
            using (var client = new KerberosClient())
            {
                var beforeStates = client.Transports.Select(t => t.Enabled).ToArray();

                KerberosInitCommand.ConfigureTransport(client, "");

                var afterStates = client.Transports.Select(t => t.Enabled).ToArray();

                CollectionAssert.AreEqual(beforeStates, afterStates);
            }
        }

        [TestMethod]
        public void ConfigureTransportUnknownDoesNothing()
        {
            using (var client = new KerberosClient())
            {
                var beforeStates = client.Transports.Select(t => t.Enabled).ToArray();

                KerberosInitCommand.ConfigureTransport(client, "unknown");

                var afterStates = client.Transports.Select(t => t.Enabled).ToArray();

                CollectionAssert.AreEqual(beforeStates, afterStates);
            }
        }

        [TestMethod]
        public void ConfigureTransportIsCaseInsensitive()
        {
            using (var client = new KerberosClient())
            {
                KerberosInitCommand.ConfigureTransport(client, "TCP");

                foreach (var t in client.Transports)
                {
                    if (t is TcpKerberosTransport)
                    {
                        Assert.IsTrue(t.Enabled, "TCP should be enabled with uppercase input");
                    }
                    else
                    {
                        Assert.IsFalse(t.Enabled, $"{t.GetType().Name} should be disabled");
                    }
                }
            }
        }
    }
}
