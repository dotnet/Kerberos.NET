using Kerberos.NET.Asn1;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class TransportTests : BaseTest
    {
        [TestMethod]
        public async Task TestTransportBase()
        {
            var transport = new NoopTransport();

            IAsn1ApplicationEncoder<KrbApReq> encoded = new KrbApReq { };

            var resp = await transport.SendMessage<KrbApReq, KrbAsRep>("sdf", encoded);

            Assert.IsNotNull(resp);
        }

        private class NoopTransport : KerberosTransportBase
        {
            public NoopTransport() { }

            public override ProtocolType Protocol => ProtocolType.Unspecified;

            public override Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req, CancellationToken cancellation = default)
            {
                var cached = QueryDomain(domain);

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

                return Task.FromResult(Decode<T>(response.ToArray()));
            }

            protected override IEnumerable<DnsRecord> Query(string lookup)
            {
                return new List<DnsRecord> {
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
                };
            }
        }
    }
}
