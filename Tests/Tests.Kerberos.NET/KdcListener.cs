using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using System;
using System.Buffers;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    internal class KdcListener : IDisposable
    {
        private readonly KdcServer server;

        private KdcListener(KdcServer server)
        {
            this.server = server;
        }

        private static readonly Random rng = new Random();

        public static int NextPort()
        {
            return rng.Next(1000, 60000);
        }

        public void Dispose() { }

        public void Stop() { }

        public static KdcListener StartListener(int port, bool slow = false)
        {
            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
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
            return await server.ProcessMessage(new ReadOnlySequence<byte>(req));
        }

        public static async Task<IRealmService> LocateRealm(string realm, bool slow = false)
        {
            IRealmService service = new FakeRealmService(realm);

            if (slow)
            {
                await Task.Delay(500);
            }

            return service;
        }
    }
}
