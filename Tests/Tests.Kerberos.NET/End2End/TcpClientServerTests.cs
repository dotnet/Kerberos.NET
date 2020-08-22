// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Transport;
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
        public async Task ClientConnectsToServer_Withtimeout()
        {
            var port = NextPort();

            using (var client = new KerberosClient($"127.0.0.1:{port}")
            {
                ConnectTimeout = TimeSpan.FromMilliseconds(1)
            })
            {
                await client.Authenticate(new KerberosPasswordCredential("test", "test", "test"));
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
            var port = NextPort();

            var threads = 20;
            var requests = 10;

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
    }
}