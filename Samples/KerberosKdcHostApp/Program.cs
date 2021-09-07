using System;
using System.Threading.Tasks;
using Kerberos.NET.Server;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
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

            var options = new ListenerOptions
            {
                Log = logger,
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => new FakeRealmService(realm)
            };

            options.Configuration.KdcDefaults.KdcTcpListenEndpoints.Clear();
            options.Configuration.KdcDefaults.KdcTcpListenEndpoints.Add("127.0.0.1:8888");
            options.Configuration.KdcDefaults.ReceiveTimeout = TimeSpan.FromHours(1);

            var listener = new KdcServiceListener(options);

            await listener.Start();

            listener.Dispose();
        }
    }
}
