using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using System;
using System.Net;
using System.Threading.Tasks;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    [EtwProfiler]
    public class KdcTcpClientEtwTraced : KdcTcpClient { }

    [RPlotExporter, RankColumn]
    public class KdcTcpClient
    {
        private int port;

        private KdcServiceListener listener;

        private readonly string user = "administrator@corp.identityintervention.com";
        private readonly string password = "P@ssw0rd!";
        private readonly string overrideKdc = $"127.0.0.1";

        [GlobalSetup]
        public void Setup()
        {
            port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => LocateRealm(realm),
                ReceiveTimeout = TimeSpan.FromHours(1)
            };

            listener = new KdcServiceListener(options);
            _ = listener.Start();
        }

        [Params(1)]
        public int AuthenticationAttempts;

        [GlobalCleanup]
        public void Teardown()
        {
            listener.Stop();
        }

        private Task<IRealmService> LocateRealm(string realm)
        {
            IRealmService service = new FakeRealmService(realm);

            return Task.FromResult(service);
        }

        [Benchmark]
        [Arguments("")]
        [Arguments("RC4")]
        [Arguments("AES128")]
        [Arguments("AES256")]
        public async Task RequestTgt(string algo)
        {
            var cred = new KerberosPasswordCredential(algo + user, password);

            var client = new KerberosClient($"{overrideKdc}:{port}");

            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                await client.Authenticate(cred);
            }
        }

        [Benchmark]
        public async Task RequestServiceTicket()
        {
            var kerbCred = new KerberosPasswordCredential(user, password);

            var client = new KerberosClient($"{overrideKdc}:{port}");

            await client.Authenticate(kerbCred);

            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                await client.GetServiceTicket(
                    "host/appservice.corp.identityintervention.com",
                    ApOptions.MutualRequired
                );
            }
        }
    }
}
