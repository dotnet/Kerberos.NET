// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosClientTests
    {
        [TestMethod]
        public void KerberosClientStartup()
        {
            using (var client = new KerberosClient())
            {
                Assert.IsNotNull(client);

                Assert.AreEqual(3, client.Transports.Count());
            }
        }

        [TestMethod]
        public void ServiceTicketsNotCached()
        {
            using (var client = new KerberosClient() { CacheServiceTickets = false })
            {
                Assert.IsNotNull(client.Cache);
                Assert.IsFalse(client.CacheServiceTickets);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void CacheCannotBeNull()
        {
            new KerberosClient { Cache = null }.Dispose();
        }

        [TestMethod]
        public void TcpClientEnabledByDefault()
        {
            using (var client = new KerberosClient())
            {
                var tcp = client.Transports.OfType<TcpKerberosTransport>().FirstOrDefault();

                Assert.IsNotNull(tcp);

                Assert.IsTrue(tcp.Enabled);
            }
        }

        [TestMethod]
        public void UdpClientDisabledByDefault()
        {
            using (var client = new KerberosClient())
            {
                var udp = client.Transports.OfType<UdpKerberosTransport>().FirstOrDefault();

                Assert.IsNotNull(udp);

                Assert.IsFalse(udp.Enabled);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public async Task ClientRequestsServiceTicketBeforeAuthentication()
        {
            using (var client = new KerberosClient())
            {
                await client.GetServiceTicket("host/test.com");
            }
        }
    }
}
