using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    //[EtwProfiler]
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

        private static readonly ConcurrentDictionary<string, KerberosPasswordCredential> Creds = new ConcurrentDictionary<string, KerberosPasswordCredential>();

        private static readonly int ProcessId = Process.GetCurrentProcess().Id;

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

        [Params("RC4", "AES128", "AES256")]
        public string AlgorithmType;

        public bool DisplayProgress { get; set; }

        [GlobalSetup]
        public Task Setup()
        {
            this.Port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, this.Port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                RealmLocator = realm => LocateRealm(realm),
                QueueLength = 10 * 1000,
                ReceiveTimeout = TimeSpan.FromMinutes(60),
                Log = null
            };

            this.listener = new KdcServiceListener(options);
            _ = this.listener.Start();

            this.credential = Creds.GetOrAdd(this.AlgorithmType, a => new KerberosPasswordCredential(a + this.user, this.password));

            this.asReq = new ReadOnlySequence<byte>(KrbAsReq.CreateAsReq(this.credential, DefaultAuthentication).EncodeApplication());

            return Task.CompletedTask;
        }

        private ReadOnlySequence<byte> asReq;
        private KerberosPasswordCredential credential;

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
            var requestCounter = 0;

            Task.WaitAll(Enumerable.Range(0, this.ConcurrentRequests).Select(taskNum => Task.Run(async () =>
            {
                var client = new KerberosClient();

                client.PinKdc(this.credential.Domain, $"{this.overrideKdc}:{this.Port}");

                for (var i = 0; i < this.AuthenticationAttempts; i++)
                {
                    await client.Authenticate(this.credential);

                    if (this.DisplayProgress)
                    {
                        CountItOut(ref requestCounter);
                    }
                }
            })).ToArray());
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
