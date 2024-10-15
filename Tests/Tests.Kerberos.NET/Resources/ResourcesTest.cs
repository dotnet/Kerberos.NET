// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class ResourcesTest : BaseTest
    {
        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void ResourceManagerFormattedResource()
        {
            var asReq = ReadDataFile(Path.Combine("Messages", "as-req"));

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
