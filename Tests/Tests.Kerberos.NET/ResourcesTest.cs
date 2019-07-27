using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ResourcesTest : BaseTest
    {
        [TestMethod, ExpectedException(typeof(CryptographicException))]
        public void TestResourceManagerFormattedResource()
        {
            var asReq = ReadDataFile("messages\\as-req");

            try
            {
                KrbError.DecodeApplication(asReq);
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.Contains("Expected Application-30"));
                throw;
            }
        }
    }
}
