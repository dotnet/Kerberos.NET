using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    [EtwProfiler]
    [RankColumn]
    //[RPlotExporter]
    //[ConcurrencyVisualizerProfiler]
    public class StressAsReq
    {
        private static IRealmService realmService;

        private KdcServiceListener listener;

        private readonly string user = "administrator@corp.identityintervention.com";
        private readonly string password = "P@ssw0rd!";
        private readonly string overrideKdc = $"127.0.0.1";

        private static readonly ConcurrentDictionary<string, KerberosPasswordCredential> Creds = new();

        private static readonly int ProcessId = Environment.ProcessId;

        private const AuthenticationOptions DefaultAuthentication =
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        public int Port { get; set; }

        [Params(1, 10, 100, 1000, 10000)]
        public int AuthenticationAttempts;

        [Params(1, 10, 100)]
        public int ConcurrentRequests;

        [Params("RC4", "AES128", "AES256", "AES128SHA256", "AES256SHA384")]
        public string AlgorithmType = "AES256";

        public bool DisplayProgress { get; set; }

        public ILoggerFactory Logger { get; set; }

        [GlobalSetup]
        public Task Setup()
        {
            this.Port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                RealmLocator = realm => LocateRealm(realm),
                Log = Logger
            };

            options.Configuration.KdcDefaults.TcpListenBacklog = int.MaxValue;
            options.Configuration.KdcDefaults.ReceiveTimeout = TimeSpan.FromSeconds(15);
            options.Configuration.KdcDefaults.KdcTcpListenEndpoints.Clear();
            options.Configuration.KdcDefaults.KdcTcpListenEndpoints.Add($"127.0.0.1:{this.Port}");

            this.listener = new KdcServiceListener(options);
            _ = this.listener.Start();

            this.credential = Creds.GetOrAdd(this.AlgorithmType, a => new KerberosPasswordCredential(a + this.user, this.password));

            this.asReq = new ReadOnlySequence<byte>(KrbAsReq.CreateAsReq(this.credential, DefaultAuthentication).EncodeApplication());

            return Task.CompletedTask;
        }

        private ReadOnlySequence<byte> asReq;
        private KerberosPasswordCredential credential;

        public int Successes;

        [GlobalCleanup]
        public void Teardown()
        {
            if (this.listener != null)
            {
                this.listener.Stop();
            }
        }

        [Benchmark]
        public void RequestTgt()
        {
            TcpKerberosTransport.MaxPoolSize = this.ConcurrentRequests * 2;

            if (this.credential == null)
            {
                this.credential = Creds.GetOrAdd(this.AlgorithmType, a => new KerberosPasswordCredential(a + this.user, this.password));
            }

            var requestCounter = 0;

            try
            {
                Task.WaitAll(Enumerable.Range(0, this.ConcurrentRequests).Select(taskNum => Task.Run(async () =>
                {
                    var client = new KerberosClient();

                    client.Transports.OfType<UdpKerberosTransport>().FirstOrDefault().Enabled = false;
                    client.Transports.OfType<HttpsKerberosTransport>().FirstOrDefault().Enabled = false;

                    client.PinKdc(this.credential.Domain, $"{this.overrideKdc}:{this.Port}");

                    for (var i = 0; i < this.AuthenticationAttempts; i++)
                    {
                        try
                        {
                            await client.Authenticate(this.credential);

                            Interlocked.Increment(ref Successes);

                            if (this.DisplayProgress)
                            {
                                CountItOut(ref requestCounter);
                            }
                        }
                        catch (Exception)
                        {
                        }
                    }
                })).ToArray());
            }
            catch
            {
            }
        }

        private static void CountItOut(ref int requestCounter)
        {
            var modDisplay = 10;

            Interlocked.Increment(ref requestCounter);

            if (requestCounter >= 1_000)
            {
                modDisplay = 100;
            }
            if (requestCounter >= 10_000)
            {
                modDisplay = 1000;
            }
            if (requestCounter >= 100_000)
            {
                modDisplay = 10000;
            }
            if (requestCounter >= 1_000_000)
            {
                modDisplay = 100000;
            }

            if (requestCounter > 0 && requestCounter % modDisplay == 0)
            {
                Console.WriteLine($"{ProcessId}: {requestCounter}");
            }
        }

        private static IRealmService LocateRealm(string realm)
        {
            realmService = realmService ?? new FakeRealmService(realm);

            return realmService;
        }
    }
}
