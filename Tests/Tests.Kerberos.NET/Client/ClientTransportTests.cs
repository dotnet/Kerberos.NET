// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Configuration;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ClientTransportTests : BaseTest
    {
        [TestMethod]
        public async Task TransportBase()
        {
            var transport = new NoopTransport();

            IAsn1ApplicationEncoder<KrbApReq> encoded = new KrbApReq { };

            var resp = await transport.SendMessage<KrbApReq, KrbAsRep>("sdf", encoded);

            Assert.IsNotNull(resp);
            transport.Dispose();
        }

        [TestMethod]
        [ExpectedException(typeof(KerberosTransportException))]
        public async Task TcpClientConnectExceptional()
        {
            using (var logger = new FakeExceptionLoggerFactory())
            {
                var tcp = new NoDnsTcpTransport(logger)
                {
                    ConnectTimeout = TimeSpan.FromSeconds(1),
                    MaximumAttempts = 1
                };

                await tcp.SendMessage<KrbApReq>("blah.com", default);

                tcp.Dispose();
            }
        }

        [TestMethod]
        public async Task ClientResolverTreatsKdcPortAsNotUri()
        {
            var server = "aaa-bbb-ccc-dc01.test.com:88";

            await ClientResolverProcessesEndpoint(server);
        }

        [TestMethod]
        public async Task ClientResolverTreatsHttpsKdcPortAsUri()
        {
            var server = "https://aaa-bbb-ccc-dc01.test.com:443/kdcproxy";

            await ClientResolverProcessesEndpoint(server);
        }

        private static async Task ClientResolverProcessesEndpoint(string server)
        {
            var client = new ClientDomainService(null)
            {
                Configuration = Krb5Config.Default()
            };

            client.Configuration.Realms["TEST.COM"].Kdc.Add(server);

            client.Configuration.Defaults.DefaultRealm = "TEST.COM";
            client.Configuration.DomainRealm.Add("TEST.COM", "TEST.COM");
            client.Configuration.Defaults.DnsLookupKdc = false;

            var result = await client.LocateKdc("TEST.COM", "_kerberos._http");

            Assert.AreEqual(1, result.Count());
            Assert.AreEqual(server, result.First().Address);
        }

        private class NoDnsTcpTransport : TcpKerberosTransport
        {
            public NoDnsTcpTransport(ILoggerFactory logger)
            : base(logger)
            {
            }

            protected override Task<DnsRecord> LocatePreferredKdc(string domain, string servicePrefix)
            {
                return Task.FromResult(new DnsRecord { Target = "127.0.0.1", Port = 12345 });
            }
        }

        private class NoopTransport : KerberosTransportBase
        {
            public NoopTransport()
                : base(null)
            {
            }

            public override ClientDomainService ClientRealmService { get; } = new NoopClientRealmService();

            public override Task<ReadOnlyMemory<byte>> SendMessage(string domain, ReadOnlyMemory<byte> req, CancellationToken cancellation = default)
            {
                var cached = this.LocateKdc(domain, "_kerberos._foo");

                Assert.IsNotNull(cached);

                var response = new KrbAsRep()
                {
                    CRealm = "sdf",
                    CName = new KrbPrincipalName { Name = new[] { "sdf" }, Type = PrincipalNameType.NT_ENTERPRISE },
                    MessageType = MessageType.KRB_AS_REP,
                    ProtocolVersionNumber = 5,
                    Ticket = new KrbTicket
                    {
                        Realm = "sdfsdf",
                        SName = new KrbPrincipalName { Name = new[] { "sdf" }, Type = PrincipalNameType.NT_ENTERPRISE },
                        EncryptedPart = new KrbEncryptedData
                        {
                            Cipher = new byte[] { 0x0, 0x0 }
                        },
                    },
                    EncPart = new KrbEncryptedData
                    {
                        Cipher = new byte[] { 0x0, 0x0 }
                    }
                }.EncodeApplication();

                return Task.FromResult(response);
            }

            private class NoopClientRealmService : ClientDomainService
            {
                public NoopClientRealmService()
                    : base(null)
                {
                }

                protected override Task<IEnumerable<DnsRecord>> Query(string domain, string servicePrefix, int defaultPort)
                {
                    return Task.FromResult<IEnumerable<DnsRecord>>(new List<DnsRecord>
                    {
                        new DnsRecord
                        {
                            Name = "sdfd",
                            Port = 0,
                            Priority = 1,
                            Target = "sdfsdfsdfsdf",
                            TimeToLive = 11,
                            Type = DnsRecordType.SRV,
                            Weight = 1
                        }
                    });
                }
            }
        }
    }
}
