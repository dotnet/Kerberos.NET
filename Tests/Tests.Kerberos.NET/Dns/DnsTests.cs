// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Dns;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DnsTests
    {
        public const string ExternalSrvRecord = "_sip._tls.syfuhs.net";

        public const string UnknownSrvRecord = "_sip._tls.internal.fake";

        public const string BadSrvRecord = "_sip._tls.internal#$@%$^&R*.fake";

        [TestMethod]
        public async Task QuerySrvRecordHittingInternet()
        {
            DnsQuery.Debug = true;

            var records = await DnsQuery.QuerySrv(ExternalSrvRecord);

            Assert.IsTrue(records.Any());

            var srv = records.Single(r => r.Type == DnsRecordType.SRV);

            Assert.AreEqual("sipdir.online.lync.com", srv.Target);
            Assert.AreEqual(443, srv.Port);
        }

        [TestMethod]
        public async Task FailedLookup()
        {
            DnsQuery.Debug = true;

            var records = await DnsQuery.QuerySrv(UnknownSrvRecord);

            Assert.AreEqual(0, records.Count());
        }

        [TestMethod]
        [ExpectedException(typeof(Win32Exception))]
        public async Task BadDataLookup()
        {
            await DnsQuery.QuerySrv(BadSrvRecord);
        }

        [TestMethod]
        public async Task QueryUsesCustomType()
        {
            var fake = new FakeDnsImplementation();

            DnsQuery.RegisterImplementation(fake);

            var result = await DnsQuery.QuerySrv("blah.blah.blah");

            Assert.AreEqual(1, result.Count());
            Assert.AreEqual("blah", result.First().Target);

            Assert.IsTrue(fake.WasCalled);

            DnsQuery.RegisterImplementation(new WindowsDnsQuery());
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void RegisteringNullFails()
        {
            DnsQuery.RegisterImplementation(null);
        }

        private class FakeDnsImplementation : IKerberosDnsQuery
        {
            public bool WasCalled { get; set; }

            public Task<IReadOnlyCollection<DnsRecord>> Query(string query, DnsRecordType type)
            {
                this.WasCalled = true;
                return Task.FromResult<IReadOnlyCollection<DnsRecord>>(new List<DnsRecord> { new DnsRecord { Target = "blah" } });
            }
        }
    }
}
