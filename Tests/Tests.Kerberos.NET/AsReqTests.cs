using Kerberos.NET.Asn1;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AsReqTests : BaseTest
    {
        [TestMethod]
        public void TestParseAsReq()
        {
            var asreqBin = ReadDataFile("messages\\as-req");

            var asreq = new KrbAsReq().Decode(new Asn1Element(asreqBin));

            Assert.IsNotNull(asreq);
        }
    }
}
