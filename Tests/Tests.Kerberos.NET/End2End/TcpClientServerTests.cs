// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Dns;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.VisualBasic.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class TcpClientServerTests : KdcListenerTestBase
    {
        private const int ConcurrentThreads = 4;
        private const int RequestsPerThread = 50;

        [TestMethod]
        public async Task ClientConnectsToServer()
        {
            var port = NextPort();

            using (var listener = StartTcpListener(port))
            {
                _ = listener.Start();

                await RequestAndValidateTickets(
                    null,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}"
                );
            }
        }

        [TestMethod]
        [ExpectedException(typeof(KerberosTransportException))]
        public async Task ClientConnectsToServer_WithTimeout()
        {
            var port = NextPort();

            using (var client = new KerberosClient()
            {
                ConnectTimeout = TimeSpan.FromMilliseconds(1)
            })
            {
                client.Configuration.Defaults.DnsLookupKdc = false;

                client.PinKdc("test", $"127.0.0.1:{port}");

                try
                {
                    await client.Authenticate(new KerberosPasswordCredential("test", "test", "test"));
                }
                catch (AggregateException agg)
                {
                    throw agg.InnerExceptions.First();
                }
            }
        }

        [TestMethod]
        public async Task ClientConnectsToServer_WithScavenge()
        {
            var port = NextPort();

            using (var listener = StartTcpListener(port))
            {
                _ = listener.Start();

                var kdc = $"127.0.0.1:{port}";

                TcpKerberosTransport.ScavengeWindow = TimeSpan.FromMilliseconds(5);

                await RequestAndValidateTickets(
                    null,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    kdc
                );

                TcpKerberosTransport.ScavengeWindow = TimeSpan.FromMilliseconds(30);
            }
        }

        [TestMethod]
        public async Task ClientConnectsWithoutPing()
        {
            var port = NextPort();

            using (var listener = StartTcpListener(port))
            {
                _ = listener.Start();

                using (var client = new KerberosClient()
                {
                    ConnectTimeout = TimeSpan.FromMilliseconds(1)
                })
                {
                    client.Configuration.Defaults.PrioritizeKdcByPing = false;

                    client.PinKdc("corp.identityintervention.com", $"127.0.0.1:{port}");

                    try
                    {
                        await client.Authenticate(new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword));
                    }
                    catch (AggregateException agg)
                    {
                        throw agg.InnerExceptions.First();
                    }
                }
            }
        }

        [TestMethod]
        public async Task ClientConnectsWithExplodingPing()
        {
            var port = NextPort();

            using (var listener = StartTcpListener(port))
            {
                _ = listener.Start();

                using (var client = new KerberosClient(transports: new PingTransport(NullLoggerFactory.Instance, port) { BlockPing = true })
                {
                    ConnectTimeout = TimeSpan.FromMilliseconds(1)
                })
                {
                    Assert.IsTrue(client.Configuration.Defaults.PrioritizeKdcByPing);

                    client.PinKdc("corp.identityintervention.com", $"127.0.0.1:{port}");

                    try
                    {
                        await client.Authenticate(new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword));
                    }
                    catch (AggregateException agg)
                    {
                        throw agg.InnerExceptions.First();
                    }
                }
            }
        }

        private class PingTransport : TcpKerberosTransport
        {
            private readonly ILoggerFactory log;
            private readonly int port;

            public PingTransport(ILoggerFactory logger, int port) : base(logger)
            {
                this.log = logger;
                this.port = port;
            }

            private ExplodyClientRealmService crs;

            public override ClientDomainService ClientRealmService => crs ??= new ExplodyClientRealmService(log)
            {
                BlockPing = this.BlockPing,
                Configuration = Krb5Config.Default()
            };

            public bool BlockPing { get; set; }

            public bool DontPing
            {
                get => this.Configuration.Defaults.PrioritizeKdcByPing;
                set => this.Configuration.Defaults.PrioritizeKdcByPing = value;
            }

            //protected override Task<DnsRecord> LocatePreferredKdc(string domain, string servicePrefix)
            //{
            //    return Task.FromResult(new DnsRecord { Target = "127.0.0.1", Port = this.port });
            //}

            private class ExplodyClientRealmService : ClientDomainService
            {
                public ExplodyClientRealmService(ILoggerFactory logger) : base(logger)
                {
                }

                public bool BlockPing { get; set; }

                protected override Task<DnsRecord> PingAsync(DnsRecord record, CancellationToken cancellationToken)
                {
                    if (BlockPing)
                    {
                        throw new PingException("Goes bang");
                    }

                    return base.PingAsync(record, cancellationToken);
                }
            }
        }


        [TestMethod]
        public async Task TCP_MultithreadedClient()
        {
            var port = NextPort();

            var threads = ConcurrentThreads;
            var requests = RequestsPerThread;

            var cacheTickets = false;
            var encodeNego = false;
            var includePac = false;

            string kdc = $"127.0.0.1:{port}";

            using (var listener = StartTcpListener(port))
            {
                _ = listener.Start();

                var exceptions = await MultithreadedRequests(
                     threads,
                     requests,
                     cacheTickets,
                     encodeNego,
                     includePac,
                     kdc,
                     null,
                     listener: null
                 );

                if (exceptions.Count > 0)
                {
                    throw new AggregateException($"Failed {exceptions.Count}", exceptions.GroupBy(e => e.GetType()).Select(e => e.First()));
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public async Task TCP_MultithreadedClient_WithLowPool()
        {
            int tries = 0;

            do
            {
                var port = NextPort();

                var threads = 20;
                var requests = 50;

                var cacheTickets = false;
                var encodeNego = false;
                var includePac = false;

                string kdc = $"127.0.0.1:{port}";

                using (var listener = StartTcpListener(port))
                {
                    _ = listener.Start();

                    var exceptions = await MultithreadedRequests(
                         threads,
                         requests,
                         cacheTickets,
                         encodeNego,
                         includePac,
                         kdc,
                         null,
                         listener: null
                     );

                    if (exceptions.Count > 0)
                    {
                        throw exceptions.First();
                    }
                }
            }
            while (++tries < 10);

            Assert.Fail("Expected multithreaded requests to eventually fail");
        }
    }
}
