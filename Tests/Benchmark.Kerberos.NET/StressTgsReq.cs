using System;
using System.Net;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    [RPlotExporter, RankColumn]
    public class StressTgsReq
    {
        private int port;

        private KdcServiceListener listener;

        private readonly string user = "administrator@corp.identityintervention.com";
        private readonly string password = "P@ssw0rd!";
        private readonly string overrideKdc = $"127.0.0.1";

        [GlobalSetup]
        public void Setup()
        {
            this.port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                IsDebug = true,
                RealmLocator = realm => this.LocateRealm(realm)
            };

            options.Configuration.KdcDefaults.ReceiveTimeout = TimeSpan.FromHours(1);
            options.Configuration.KdcDefaults.KdcTcpListenEndpoints.Clear();
            options.Configuration.KdcDefaults.KdcTcpListenEndpoints.Add($"127.0.0.1:{this.port}");

            this.listener = new KdcServiceListener(options);
            _ = this.listener.Start();
        }

        [Params(1, 10, 100, 1000, 10000)]
        public int AuthenticationAttempts;

        [GlobalCleanup]
        public void Teardown()
        {
            this.listener.Stop();
        }

        private IRealmService LocateRealm(string realm)
        {
            return new FakeRealmService(realm);
        }

        [Benchmark]
        [Arguments("")]
        [Arguments("RC4")]
        [Arguments("AES128")]
        [Arguments("AES256")]
        public async Task RequestServiceTicket(string algo)
        {
            var kerbCred = new KerberosPasswordCredential(algo + this.user, this.password);

            using (var client = new KerberosClient())
            {
                client.PinKdc(kerbCred.Domain, $"{this.overrideKdc}:{this.port}");

                await client.Authenticate(kerbCred);

                for (var i = 0; i < this.AuthenticationAttempts; i++)
                {
                    await client.GetServiceTicket(
                        "host/appservice.corp.identityintervention.com",
                        ApOptions.MutualRequired
                    );
                }
            }
        }
    }
}
