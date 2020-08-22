// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;

namespace Tests.Kerberos.NET
{
    internal class KdcListener : IDisposable
    {
        private readonly KdcServer server;

        private KdcListener(KdcServer server)
        {
            this.server = server;
        }

        private static readonly Random Rng = new Random();

        public static int NextPort()
        {
            return Rng.Next(1000, 60000);
        }

        public void Dispose()
        {
        }

        public static TcpKdcListener StartTcpListener(int port, bool slow = false)
        {
            var options = new KdcServerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(CultureInfo.InvariantCulture),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm, slow),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            KdcServiceListener server = new KdcServiceListener(options);

            return new TcpKdcListener(server);
        }

        public static KdcListener StartListener(int port, bool slow = false)
        {
            var options = new KdcServerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(CultureInfo.InvariantCulture),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm, slow),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            var server = new KdcServer(options);

            server.RegisterPreAuthHandler(
                PaDataType.PA_PK_AS_REQ,
                service => new PaDataPkAsReqHandler(service) { IncludeOption = X509IncludeOption.EndCertOnly }
            );

            return new KdcListener(server);
        }

        internal async Task<ReadOnlyMemory<byte>> Receive(ReadOnlyMemory<byte> req)
        {
            return await this.server.ProcessMessage(req);
        }

        public static IRealmService LocateRealm(string realm, bool slow = false)
        {
            IRealmService service = new FakeRealmService(realm);

            if (slow)
            {
                Thread.Sleep(500);
            }

            return service;
        }
    }
}