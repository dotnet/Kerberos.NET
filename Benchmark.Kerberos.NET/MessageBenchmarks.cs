using BenchmarkDotNet.Attributes;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Buffers;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    //[EtwProfiler]
    [RankColumn]
    [RPlotExporter]
    //[ConcurrencyVisualizerProfiler]
    public class MessageBenchmarks
    {
        private readonly string user = "administrator@corp.identityintervention.com";
        private readonly string password = "P@ssw0rd!";

        private static readonly ConcurrentDictionary<string, KerberosPasswordCredential> Creds = new ConcurrentDictionary<string, KerberosPasswordCredential>();

        private const AuthenticationOptions DefaultAuthentication =
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        [Params(1, 10, 100, 1000, 10000)]
        public int AuthenticationAttempts;

        [Params("RC4", "AES128", "AES256")]
        public string AlgorithmType;

        [GlobalSetup]
        public Task Setup()
        {
            options = new ListenerOptions
            {
                DefaultRealm = Realm,
                RealmLocator = LocateRealm
            };

            credential = Creds.GetOrAdd(AlgorithmType, a => new KerberosPasswordCredential(a + user, password));

            asReq = new ReadOnlySequence<byte>(KrbAsReq.CreateAsReq(credential, DefaultAuthentication).EncodeApplication());

            return Task.CompletedTask;
        }

        private ListenerOptions options;
        private ReadOnlySequence<byte> asReq;
        private KerberosPasswordCredential credential;

        [GlobalCleanup]
        public void Teardown()
        {
        }

        [Benchmark]
        public async Task ProcessAsReq()
        {
            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                KdcAsReqMessageHandler handler = new KdcAsReqMessageHandler(asReq, options);

                var response = await handler.Execute();

                Assert.IsNotNull(response);
            }
        }

        private static readonly byte[] TgtKey = new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };

        private const string Realm = "corp.test.internal";
        private const string UserUpn = "user@test.internal";

        [Benchmark]
        public async Task GenerateTgt()
        {
            var realmService = new FakeRealmService(Realm);
            var principal = await realmService.Principals.Find(UserUpn);

            var principalKey = await principal.RetrieveLongTermCredential();

            var rst = new ServiceTicketRequest
            {
                Flags = TicketFlags.EncryptedPreAuthentication | TicketFlags.Renewable | TicketFlags.Forwardable,
                Principal = principal,
                EncryptedPartKey = principalKey,
                ServicePrincipalKey = new KerberosKey(key: TgtKey, etype: EncryptionType.AES256_CTS_HMAC_SHA1_96)
            };

            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                var tgt = await KrbAsRep.GenerateTgt(rst, realmService);

                Assert.IsNotNull(tgt);
            }
        }

        private static Task<IRealmService> LocateRealm(string realm)
        {
            IRealmService realmService = new FakeRealmService(realm);

            return Task.FromResult(realmService);
        }
    }
}
