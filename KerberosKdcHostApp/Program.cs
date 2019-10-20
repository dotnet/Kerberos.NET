using Kerberos.NET.Server;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using System;
using System.Net;
using System.Threading.Tasks;
using Tests.Kerberos.NET;

namespace KerberosKdcHostApp
{
    class Program
    {
        static async Task Main()
        {
            var builder = new HostBuilder()
                .ConfigureLogging((_, factory) =>
                {
                    factory.AddConsole(opt => opt.IncludeScopes = true);
                    factory.AddFilter<ConsoleLoggerProvider>(level => level >= LogLevel.Trace);
                });

            var host = builder.Build();

            var logger = (ILoggerFactory)host.Services.GetService(typeof(ILoggerFactory));

            KdcServiceListener listener = new KdcServiceListener(new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, 8888),
                Log = logger,
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            });

            await listener.Start();

            listener.Dispose();
        }

        private static Task<IRealmService> LocateRealm(string realm)
        {
            IRealmService service = new FakeRealmService(realm);

            return Task.FromResult(service);
        }
    }
}
