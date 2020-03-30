using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Kerberos.NET.Dns;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class TcpClientPoolTests
    {
        [TestMethod]
        public void CreateSocketPool()
        {
            var pool = TcpKerberosTransport.CreateSocketPool();

            Assert.IsNotNull(pool);
        }

        [TestMethod]
        public void DisposeSocketPool()
        {
            using (var pool = TcpKerberosTransport.CreateSocketPool())
            {
                Assert.IsNotNull(pool);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public async Task Request_MaxSize()
        {
            var port = NextPort();

            var listener = new TcpListener(IPAddress.Loopback, port);

            try
            {
                listener.Start();

                using (var pool = TcpKerberosTransport.CreateSocketPool())
                {
                    pool.MaxPoolSize = 1;

                    for (var i = 0; i < pool.MaxPoolSize + 1; i++)
                    {
                        await pool.Request(new DnsRecord { Target = "127.0.0.1", Port = port }, TimeSpan.FromMilliseconds(500));
                    }
                }
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public async Task Request_WithRelease()
        {
            var port = NextPort();

            var listener = new TcpListener(IPAddress.Loopback, port);

            try
            {
                listener.Start();

                using (var pool = TcpKerberosTransport.CreateSocketPool())
                {
                    pool.MaxPoolSize = 1;

                    for (var i = 0; i < pool.MaxPoolSize + 1; i++)
                    {
                        var req = await pool.Request(
                            new DnsRecord { Target = "127.0.0.1", Port = port }, 
                            TimeSpan.FromMilliseconds(500)
                        );

                        req.Dispose();
                    }
                }
            }
            finally
            {
                listener.Stop();
            }
        }

        [TestMethod]
        public async Task Request_WithScavenge()
        {
            var port = NextPort();

            var listener = new TcpListener(IPAddress.Loopback, port);

            try
            {
                listener.Start();

                using (var pool = TcpKerberosTransport.CreateSocketPool())
                {
                    for (var i = 0; i < pool.MaxPoolSize + 1; i++)
                    {
                        var req = await pool.Request(new DnsRecord { Target = "127.0.0.1", Port = port }, TimeSpan.FromMilliseconds(500));

                        req.Dispose();
                    }
                }
            }
            finally
            {
                listener.Stop();
            }
        }
    }
}
