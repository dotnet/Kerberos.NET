using Kerberos.NET.Dns;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.ComponentModel;
using System.Linq;

namespace Tests.Kerberos.NET.Dns
{
    [TestClass]
    public class DnsTests
    {
        public const string ExternalSrvRecord = "_sip._tls.syfuhs.net";

        public const string UnknownSrvRecord = "_sip._tls.internal.fake";

        public const string BadSrvRecord = "_sip._tls.internal#$@%$^&R*.fake";

        [TestMethod]
        public void TestQuerySrvRecordHittingInternet()
        {
            DnsQuery.Debug = true;

            var records = DnsQuery.QuerySrv(ExternalSrvRecord);

            Assert.IsTrue(records.Count() > 0);

            var srv = records.Single(r => r.Type == DnsRecordType.SRV);

            Assert.AreEqual("sipdir.online.lync.com", srv.Target);
            Assert.AreEqual(443, srv.Port);
        }

        [TestMethod]
        public void TestFailedLookup()
        {
            var records = DnsQuery.QuerySrv(UnknownSrvRecord);

            Assert.AreEqual(0, records.Count());
        }

        [TestMethod, ExpectedException(typeof(Win32Exception))]
        public void TestBadDataLookup()
        {
            DnsQuery.QuerySrv(BadSrvRecord);
        }
    }
}
