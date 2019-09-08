using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using Kerberos.NET.Server;
using System;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using System.Net;
using System.Threading.Tasks;
using static Tests.Kerberos.NET.E2EKdcClientTest;
using System.Linq;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading;
using System.Buffers;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Benchmark.Kerberos.NET
{
    [EtwProfiler]
    [RankColumn]
    //[RPlotExporter]
    //[ConcurrencyVisualizerProfiler]
    public class Stress
    {
        public int Port { get; set; }

        private KdcServiceListener listener;

        private readonly string user = "administrator@corp.identityintervention.com";
        private readonly string password = "P@ssw0rd!";
        private readonly string overrideKdc = $"127.0.0.1";

        [GlobalSetup]
        public void Setup()
        {
            Port = new Random().Next(20000, 40000);

            var options = new ListenerOptions
            {
                ListeningOn = new IPEndPoint(IPAddress.Loopback, Port),
                DefaultRealm = "corp2.identityintervention.com".ToUpper(),
                RealmLocator = realm => LocateRealm(realm),
                QueueLength = 10 * 1000,
                ReceiveTimeout = TimeSpan.FromMinutes(60),
                Log = null
            };

            listener = new KdcServiceListener(options);
            _ = listener.Start();
        }

        [GlobalCleanup]
        public void Teardown()
        {
            if (listener != null)
            {
                listener.Stop();
            }
        }

        [Params(1, 10, 100, 1000, 10000)]
        public int AuthenticationAttempts;

        [Params(1, 10, 100)]
        public int ConcurrentRequests;

        [Params("RC4", "AES128", "AES256")]
        public string AlgorithmType;

        public bool DisplayProgress { get; set; }

        private static IRealmService realmService;

        private static Task<IRealmService> LocateRealm(string realm)
        {
            realmService ??= realmService = new FakeRealmService(realm);

            return Task.FromResult(realmService);
        }

        private readonly Random random = new Random();

        private static readonly string[] Algorithms = new string[] { "RC4", "AES128", "AES256" };

        private static readonly ConcurrentDictionary<string, KerberosPasswordCredential> Creds = new ConcurrentDictionary<string, KerberosPasswordCredential>();

        private static readonly int ProcessId = Process.GetCurrentProcess().Id;

        private const AuthenticationOptions DefaultAuthentication =
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        [Benchmark]
        public async Task ProcessAsReq()
        {
            var requestCounter = 0;

            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                var credential = Creds.GetOrAdd(AlgorithmType, a => new KerberosPasswordCredential(a + user, password));

                var asReq = KrbAsReq.CreateAsReq(credential, DefaultAuthentication).EncodeApplication();

                var message = new ReadOnlySequence<byte>(asReq);

                KdcAsReqMessageHandler handler = new KdcAsReqMessageHandler(message, listener.Options);

                var response = await handler.Execute();

                Assert.IsNotNull(response);

                if (DisplayProgress)
                {
                    CountItOut(ref requestCounter);
                }
            }
        }

        [Benchmark]
        public void RequestTgt()
        {
            var requestCounter = 0;

            Task.WaitAll(Enumerable.Range(0, ConcurrentRequests).Select(taskNum => Task.Run(async () =>
            {
                var algo = Algorithms[random.Next(0, Algorithms.Length - 1)];

                var cred = Creds.GetOrAdd(algo, a => new KerberosPasswordCredential(a + user, password));

                var client = new KerberosClient($"{overrideKdc}:{Port}");

                for (var i = 0; i < AuthenticationAttempts; i++)
                {
                    await client.Authenticate(cred);

                    if (DisplayProgress)
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
    }
}
