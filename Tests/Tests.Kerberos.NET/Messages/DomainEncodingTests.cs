// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DomainEncodingTests
    {
        private static readonly Dictionary<string, string[]> EncodingTestCases = new()
        {
            { "\"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.\".", new[] { "EDU", "MIT.EDU", "ATHENA.MIT.EDU", "WASHINGTON.EDU", "CS.WASHINGTON.EDU" } },
            { "\"EDU,MIT.,WASHINGTON.EDU\"", new[] { "EDU", "MIT.EDU", "WASHINGTON.EDU" } }
        };

        [TestMethod]
        public void DomainX500Encoding()
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

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void DomainX500EncodingSlashes()
        {
            var encoding = new KrbTransitedEncoding();

            encoding.EncodeTransit(new[] { "/COM/HP/APOLLO", "/COM/HP", "/COM" });
        }

        [TestMethod]
        [ExpectedException(typeof(InvalidOperationException))]
        public void DomainX500DecodingSlashes()
        {
            var encoding = new KrbTransitedEncoding()
            {
                Type = TransitedEncodingType.DomainX500Compress,
                Contents = new ReadOnlyMemory<byte>(Encoding.UTF8.GetBytes("\"/COM,/HP,/APOLLO, /COM/DEC\"."))
            };

            encoding.DecodeTransit();
        }
    }
}