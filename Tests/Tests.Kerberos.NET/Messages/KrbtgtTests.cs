using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.ComTypes;
using System.Text;

namespace Tests.Kerberos.NET.Messages
{
    [TestClass]
    public class KrbtgtTests : BaseTest
    {
        private static readonly byte[] key = new byte[]
        {
            0xef, 0x74, 0x22, 0xcb, 0x49, 0xe2, 0xf5, 0xb0, 0x92, 0x92, 0xcb, 0xd8, 0x25, 0xc2, 0x95, 0x24,
            0x9f, 0x2a, 0x31, 0x46, 0x5d, 0xc9, 0xab, 0x4a, 0x30, 0x80, 0xed, 0xf3, 0x16, 0x8a, 0x88, 0x57
        };

        [TestMethod]
        public void TestKrbtgtDecode()
        {
            var krbtgtKey = new KerberosKey(key: key);
            var longUserTermKey = new KerberosKey("P@ssw0rd!", salt: "CORP.IDENTITYINTERVENTION.COMtestuser");

            var krbAsRepBytes = ReadDataFile("messages\\as-rep").Skip(4).ToArray();

            var asRep = new KrbAsRep().DecodeAsApplication(krbAsRepBytes);

            var encPart = asRep.Response.EncPart.Decrypt(longUserTermKey, KeyUsage.EncAsRepPart, b => KrbEncAsRepPart.Decode(b));

            Assert.IsNotNull(encPart);

            var encTicket = asRep.Response.Ticket.Application.EncryptedPart;

            var krbtgt = encTicket.Decrypt(krbtgtKey, KeyUsage.Ticket, bytes => new KrbEncTicketPart().DecodeAsApplication(bytes));

            Assert.IsNotNull(krbtgt);
        }

        private static readonly Dictionary<string, string[]> EncodingTestCases = new Dictionary<string, string[]>
        {
            { "\"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.\".", new[] { "EDU", "MIT.EDU", "ATHENA.MIT.EDU", "WASHINGTON.EDU", "CS.WASHINGTON.EDU" } },
            { "\"EDU,MIT.,WASHINGTON.EDU\"", new [] { "EDU", "MIT.EDU", "WASHINGTON.EDU" } }
        };

        [TestMethod]
        public void TestDomainX500Encoding()
        {
            foreach (var kv in EncodingTestCases)
            {
                var encoding = new KrbTransitedEncoding();

                encoding.EncodeTransit(kv.Value);

                string encoded = Encoding.UTF8.GetString(encoding.Contents.ToArray());

                Assert.AreEqual(kv.Key, encoded);

                var decodedRealms = encoding.DecodeTransit();

                Assert.IsTrue(kv.Value.SequenceEqual(decodedRealms));
            }
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void TestDomainX500EncodingSlashes()
        {
            var encoding = new KrbTransitedEncoding();

            encoding.EncodeTransit(new[] { "/COM/HP/APOLLO", "/COM/HP", "/COM" });
        }

        [TestMethod, ExpectedException(typeof(InvalidOperationException))]
        public void TestDomainX500DecodingSlashes()
        {
            var encoding = new KrbTransitedEncoding()
            {
                Type = TransitedEncodingType.DomainX500Compress,
                Contents = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("\"/COM,/HP,/APOLLO, /COM/DEC\"."))
            };

            encoding.DecodeTransit();
        }

        [TestMethod]
        public void TestTgsParse()
        {
            var tgsReqBytes = ReadDataFile("messages\\tgs-req-testuser-host-app03").Skip(4).ToArray();

            var tgsReq = KrbTgsReq.DecodeMessageAsApplication(tgsReqBytes);

            var paData = tgsReq.TgsReq.PaData.First(p => p.Type == PaDataType.PA_TGS_REQ);

            var apReq = paData.DecodeApReq();

            var krbtgtKey = new KerberosKey(key: key);

            var krbtgt = apReq.Ticket.Application.EncryptedPart.Decrypt(krbtgtKey, KeyUsage.Ticket, b => new KrbEncTicketPart().DecodeAsApplication(b));

            Assert.AreEqual("testuser", krbtgt.CName.FullyQualifiedName);
        }
    }
}
