using System;
using System.Collections.Concurrent;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    [EtwProfiler]
    //[MemoryDiagnoser]
    //[NativeMemoryProfiler]
    //[ConcurrencyVisualizerProfiler]
    [RankColumn, RPlotExporter]
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

        private EncryptionType etype;

        [GlobalSetup]
        public void Setup()
        {
            options = new ListenerOptions
            {
                DefaultRealm = Realm,
                RealmLocator = LocateRealm
            };

            credential = Creds.GetOrAdd(AlgorithmType, a => new KerberosPasswordCredential(a + user, password));

            asReq = KrbAsReq.CreateAsReq(credential, DefaultAuthentication).EncodeApplication();

            switch (AlgorithmType)
            {
                case "RC4":
                    etype = EncryptionType.RC4_HMAC_NT;
                    break;
                case "AES128":
                    etype = EncryptionType.AES128_CTS_HMAC_SHA1_96;
                    break;
                case "AES256":
                    etype = EncryptionType.AES256_CTS_HMAC_SHA1_96;
                    break;
            }
        }

        private ListenerOptions options;
        private ReadOnlyMemory<byte> asReq;
        private KerberosPasswordCredential credential;

        [GlobalCleanup]
        public void Teardown()
        {
        }

        [Benchmark]
        public void ProcessAsReq()
        {
            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                KdcAsReqMessageHandler handler = new KdcAsReqMessageHandler(asReq, options);

                var response = handler.Execute();

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
        public void GenerateTgt()
        {
            var realmService = new FakeRealmService(Realm);
            var principal = realmService.Principals.Find(KrbPrincipalName.FromString(UserUpn));

            var principalKey = principal.RetrieveLongTermCredential();

            var rst = new ServiceTicketRequest
            {
                Flags = TicketFlags.EncryptedPreAuthentication | TicketFlags.Renewable | TicketFlags.Forwardable,
                Principal = principal,
                EncryptedPartKey = principalKey,
                ServicePrincipalKey = new KerberosKey(key: TgtKey, etype: etype, kvno: 123)
            };

            for (var i = 0; i < AuthenticationAttempts; i++)
            {
                var tgt = KrbAsRep.GenerateTgt(rst, realmService);

                Assert.IsNotNull(tgt);
            }
        }

        private static IRealmService LocateRealm(string realm)
        {
            return new FakeRealmService(realm);
        }
    }
}
