using Kerberos.NET.Client;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading.Tasks;

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

                Assert.AreEqual(2, client.Transports.Count());
            }
        }

        [TestMethod]
        public void ServiceTicketsCached()
        {
            using (var client = new KerberosClient())
            {
                Assert.IsNotNull(client.Cache);
                Assert.IsTrue(client.CacheServiceTickets);
            }
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void CacheCannotBeNull()
        {
#pragma warning disable IDE0067 // Dispose objects before losing scope
            _ = new KerberosClient { Cache = null };
#pragma warning restore IDE0067 // Dispose objects before losing scope
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

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public async Task ClientRequestsServiceTicketBeforeAuthentication()
        {
            using (var client = new KerberosClient())
            {
                await client.GetServiceTicket("host/test.com");
            }
        }
    }
}
