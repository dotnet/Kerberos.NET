using System;
using System.Collections.Generic;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Server;
using Tests.Kerberos.NET;

namespace Benchmark.Kerberos.NET
{
    [EtwProfiler]
    [MemoryDiagnoser]
    [NativeMemoryProfiler]
    [RankColumn, RPlotExporter]

    public class PacEncodingBenchmarks
    {
        private IKerberosPrincipal principal;
        private PrivilegedAttributeCertificate pac;
        private KerberosKey key;

        [Params(0, 1, 5, 10, 100, 1000)]
        public int GroupSize { get; set; }

        [Params(0, 1, 5, 10, 100, 1000)]
        public int ExtraSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            var realmService = new FakeRealmService("CORP.BLAH.COM");

            this.principal = realmService.Principals.Find(KrbPrincipalName.FromString("user@test.com"));
            this.pac = this.principal.GeneratePac();
            this.key = new KerberosKey(new byte[32], etype: EncryptionType.AES256_CTS_HMAC_SHA1_96);

            var groups = new List<GroupMembership>();

            for (var i = 0; i < this.GroupSize; i++)
            {
                groups.Add(new GroupMembership
                {
                    Attributes = SidAttributes.SE_GROUP_ENABLED | SidAttributes.SE_GROUP_MANDATORY,
                    RelativeId = (uint)i
                });
            }

            this.pac.LogonInfo.GroupIds = groups;

            var extra = new List<RpcSidAttributes>();

            for (var i = 0; i < this.ExtraSize; i++)
            {
                extra.Add(new RpcSidAttributes
                {
                    Attributes = SidAttributes.SE_GROUP_ENABLED | SidAttributes.SE_GROUP_MANDATORY,
                    Sid = new RpcSid()
                    {
                        IdentifierAuthority = new RpcSidIdentifierAuthority
                        {
                            IdentifierAuthority = new byte[] { 0, 0, 0, 0, 0, (byte)IdentifierAuthority.NTAuthority }
                        },
                        SubAuthority = new uint[] { 21, 3333, 4444, 5555, 111 },
                        Revision = 1
                    }
                });
            }

            this.pac.LogonInfo.ExtraIds = extra;
        }

        [Benchmark]
        public ReadOnlyMemory<byte> Encode()
        {
            return this.pac.Encode(this.key, this.key);
        }
    }
}
