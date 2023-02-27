// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AllMessagesTests : BaseTest
    {
        [TestMethod]
        public void Message_AsRep()
        {
            var file = ReadDataFile(Path.Combine("Messages", "as-rep"));

            var decoded = TestSimpleRoundtrip(
                "as-rep",
                file.Skip(4).ToArray(),
                v => new KrbAsRep().DecodeAsApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_AsReq()
        {
            var file = ReadDataFile(Path.Combine("Messages", "as-req"));

            var decoded = TestSimpleRoundtrip(
                "as-req",
                file.Skip(4).ToArray(),
                v => KrbAsReq.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_AsReqPreAuth()
        {
            var file = ReadDataFile(Path.Combine("Messages", "as-req-preauth"));

            var decoded = TestSimpleRoundtrip(
                "as-req-preauth",
                file.Skip(4).ToArray(),
                v => KrbAsReq.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_KrbErrorPreAuth()
        {
            var file = ReadDataFile(Path.Combine("Messages", "krb-error-preauth-required"));

            var decoded = TestSimpleRoundtrip(
                "krb-error-preauth-required",
                file.Skip(4).ToArray(),
                v => KrbError.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsRep()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-rep-testuser-host-app03"));

            var decoded = TestSimpleRoundtrip(
                "tgs-rep-testuser-host-app03",
                file.Skip(4).ToArray(),
                v => KrbTgsRep.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsRepKrbTgtRenew()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-rep-testuser-krbtgt-renew"));

            var decoded = TestSimpleRoundtrip(
                "tgs-rep-testuser-krbtgt-renew",
                file.Skip(4).ToArray(),
                v => KrbTgsRep.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsReq()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-req-testuser-host-app03"));

            var decoded = TestSimpleRoundtrip(
                "tgs-req-testuser-host-app03",
                file.Skip(4).ToArray(),
                v => KrbTgsReq.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsReqKrbTgtRenew()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-req-testuser-krbtgt-renew"));

            var decoded = TestSimpleRoundtrip(
                "tgs-req-testuser-krbtgt-renew",
                file.Skip(4).ToArray(),
                v => KrbTgsReq.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsReqS4uSelf()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-req-app2-s4u-self"));

            var decoded = TestSimpleRoundtrip(
                "tgs-req-app2-s4u-self",
                file.Skip(4).ToArray(),
                v => KrbTgsReq.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsRepS4uSelf()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-rep-app2-s4u-self"));

            var decoded = TestSimpleRoundtrip(
                "tgs-rep-app2-s4u-self",
                file.Skip(4).ToArray(),
                v => KrbTgsRep.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsReqS4uProxy()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-req-app2-s4u-proxy"));

            var decoded = TestSimpleRoundtrip(
                "tgs-req-app2-s4u-proxy",
                file.Skip(4).ToArray(),
                v => KrbTgsReq.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void Message_TgsRepS4uProxy()
        {
            var file = ReadDataFile(Path.Combine("Messages", "tgs-rep-app2-s4u-proxy"));

            var decoded = TestSimpleRoundtrip(
                "tgs-rep-app2-s4u-proxy",
                file.Skip(4).ToArray(),
                v => KrbTgsRep.DecodeApplication(v),
                t => t.EncodeApplication().ToArray()
            );

            Assert.IsNotNull(decoded);
        }

        private static T TestSimpleRoundtrip<T>(string key, byte[] value, Func<byte[], T> decode, Func<T, byte[]> encode)
        {
            var thing = decode(value);

            var encoded = encode(thing);

            Debug.WriteLine(value.HexDump());

            Debug.WriteLine(encoded.HexDump());

            Assert.IsTrue(value.SequenceEqual(encoded), key);

            return thing;
        }
    }
}
