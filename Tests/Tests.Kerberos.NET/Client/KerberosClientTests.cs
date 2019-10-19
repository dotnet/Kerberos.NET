using Kerberos.NET.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Net.Sockets;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KerberosClientTests
    {
        [TestMethod]
        public void KerberosClientStartup()
        {
            using var client = new KerberosClient();

            Assert.IsNotNull(client);

            Assert.AreEqual(2, client.Transports.Count());
        }

        [TestMethod]
        public void ServiceTicketsNotCached()
        {
            using var client = new KerberosClient();

            Assert.IsNotNull(client.Cache);
            Assert.IsFalse(client.CacheServiceTickets);
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void CacheCannotBeNull()
        {
            using var client = new KerberosClient
            {
                Cache = null
            };
        }

        [TestMethod]
        public void TcpClientEnabledByDefault()
        {
            using var client = new KerberosClient();

            var tcp = client.Transports.FirstOrDefault(t => t.Protocol == ProtocolType.Tcp);

            Assert.IsNotNull(tcp);

            Assert.IsTrue(tcp.Enabled);
        }

        [TestMethod]
        public void UdpClientDisabledByDefault()
        {
            using var client = new KerberosClient();

            var udp = client.Transports.FirstOrDefault(t => t.Protocol == ProtocolType.Udp);

            Assert.IsNotNull(udp);

            Assert.IsFalse(udp.Enabled);
        }
    }
}
