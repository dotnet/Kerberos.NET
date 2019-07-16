using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KdcReqTests : BaseTest
    {
        [TestMethod]
        public void TestParseAsReq()
        {
            var asReqBin = ReadDataFile("messages\\as-req").Skip(4).ToArray();

            var asreq = KrbAsReq.DecodeAsApplication(asReqBin);

            Assert.IsNotNull(asreq);

            var bytes = asreq.Encode();

            Assert.IsTrue(bytes.Length > 0);
        }

        [TestMethod]
        public void TestParseAsReqWithPaData()
        {
            var asReqBin = ReadDataFile("messages\\as-req-preauth").Skip(4).ToArray();

            var asreq = KrbAsReq.DecodeAsApplication(asReqBin);

            Assert.IsNotNull(asreq);

            var bytes = asreq.Encode();

            Assert.IsTrue(bytes.Length > 0);
        }
    }
}
