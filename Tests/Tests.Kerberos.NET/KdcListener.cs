using Kerberos.NET.Server;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    internal static class KdcListener
    {
        private static readonly Random rng = new Random();

        public static int NextPort()
        {
            return rng.Next(20000, 40000);
        }

        public static KdcServiceListener StartListener(int port, bool slow = false)
        {
            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm, slow),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            var listener = new KdcServiceListener(options);

            _ = listener.Start();

            return listener;
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
