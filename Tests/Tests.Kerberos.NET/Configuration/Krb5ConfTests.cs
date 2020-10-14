﻿// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class Krb5ConfTests : BaseTest
    {
        [TestMethod]
        public void ParseBasicConfiguration()
        {
            var conf = ParseConfiguration();

            var roundtrip = Krb5ConfigurationSerializer.Serialize(conf);

            var conf2 = Krb5ConfigurationSerializer.Deserialize(roundtrip);

            Assert.IsNotNull(conf2);

            Assert.AreEqual(conf.Get<bool>("appdefaults.kadmin.forwardable"), conf2.Get<bool>("appdefaults.kadmin.forwardable"));
        }

        [TestMethod]
        public void ParseHandlesEndOfConfig()
        {
            var conf = ParseConfiguration();

            var kdcs = conf.Get<IEnumerable<string>>("realms.\"EXAMPLE.COM\".kdc");

            Assert.AreEqual(3, kdcs.Count());

            for (var i = 1; i <= 3; i++)
            {
                Assert.AreEqual($"srv-kdc-{i}.EXAMPLE.COM:88", kdcs.ElementAt(i - 1));
            }
        }

        [TestMethod]
        public void ParseConfigToConfigObject()
        {
            var conf = ParseConfiguration();

            var obj = conf.ToConfigObject();

            Assert.IsNotNull(obj);

            Assert.AreEqual(1, obj.CaPaths.Count);
            Assert.AreEqual(".", obj.CaPaths["EXAMPLE.COM"]["DEV.EXAMPLE.COM"]);
            Assert.AreEqual(".", obj.CaPaths["EXAMPLE.COM"]["TEST.EXAMPLE.COM"]);
        }

        [TestMethod]
        public void ConfigToSectionList()
        {
            var conf = ParseConfiguration();

            var obj = conf.ToConfigObject();

            var sectionList = ConfigurationSectionList.FromConfigObject(obj);

            Assert.IsNotNull(sectionList);

            var obj2 = sectionList.ToConfigObject();

            Assert.IsNotNull(obj2);

            Assert.AreEqual(obj.Defaults.DefaultCCacheName, obj2.Defaults.DefaultCCacheName);
            Assert.AreEqual(obj.Defaults.DefaultRealm, obj2.Defaults.DefaultRealm);

            Assert.AreEqual(1, obj.Realms.Count);
            Assert.AreEqual(3, obj.Realms["EXAMPLE.COM"].Kdc.Count());

            Assert.AreEqual(obj.CaPaths["EXAMPLE.COM"]["DEV.EXAMPLE.COM"], obj2.CaPaths["EXAMPLE.COM"]["DEV.EXAMPLE.COM"]);
            Assert.AreEqual(obj.CaPaths["EXAMPLE.COM"]["TEST.EXAMPLE.COM"], obj2.CaPaths["EXAMPLE.COM"]["TEST.EXAMPLE.COM"]);
            Assert.AreEqual(obj.CaPaths["EXAMPLE.COM"].Count, obj2.CaPaths["EXAMPLE.COM"].Count);

            for (var i = 0; i < obj.Defaults.DefaultTgsEncTypes.Count(); i++)
            {
                Assert.AreEqual(obj.Defaults.DefaultTgsEncTypes.ElementAt(i), obj2.Defaults.DefaultTgsEncTypes.ElementAt(i));
            }
        }

        [TestMethod]
        public void ParsesListEnum()
        {
            var conf = ParseConfiguration();

            var obj = conf.ToConfigObject();

            Assert.AreEqual(1, obj.Defaults.PermittedEncryptionTypes.Count());

            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, obj.Defaults.PermittedEncryptionTypes.ElementAt(0));
        }

        [TestMethod]
        public void TraverseSettingsByKey()
        {
            var conf = ParseConfiguration();

            var fwd = conf.Get<bool>("appdefaults.kadmin.forwardable");

            Assert.IsTrue(fwd);
        }

        [TestMethod]
        public void DefaultsAreHandled()
        {
            var emptyObj = new Krb5Config().Serialize();

            var obj = Krb5ConfigurationSerializer.Deserialize(emptyObj).ToConfigObject();

            Assert.AreEqual(5, obj.Defaults.DefaultTgsEncTypes.Count());
        }

        [TestMethod]
        public void DefaultWithNewCtor()
        {
            var config = new Krb5Config();

            Assert.AreEqual(5, config.Defaults.DefaultTgsEncTypes.Count());
        }

        [TestMethod]
        public void TraverseQuotedSettings()
        {
            var conf = ParseConfiguration();

            var value = conf.Get<string>("realms.\"EXAMPLE.COM\".v4_name_convert.host.rcmd");

            Assert.AreEqual("host", value);
        }

        [TestMethod]
        public void TraverseMultiQuotedSettings()
        {
            var conf = ParseConfiguration();

            var value = conf.Get<string>("capaths.\"EXAMPLE.COM\".\"DEV.EXAMPLE.COM\"");

            Assert.AreEqual(".", value);
        }

        [TestMethod]
        public void ParseUnknownSetting()
        {
            var conf = ParseConfiguration();

            var value = conf.Get<string>("foo.bar.baz");

            Assert.IsNull(value);
        }

        [TestMethod]
        public void ParseTimeSpanSingle()
        {
            var conf = ParseConfiguration();

            var ts = conf.Get<TimeSpan>("libdefaults.ticket_lifetime");

            Assert.AreEqual(new TimeSpan(0, 26, 0, 0), ts);
        }

        [TestMethod]
        public void ParseTimeSpan()
        {
            var conf = ParseConfiguration();

            var ts = conf.Get<TimeSpan>("libdefaults.default_lifetime");

            Assert.AreEqual(new TimeSpan(13, 0, 13, 15), ts);
        }

        [TestMethod]
        public void ParseList()
        {
            var conf = ParseConfiguration();

            var list = conf.Get<IEnumerable<EncryptionType>>("libdefaults.default_tgs_enctypes");

            Assert.AreEqual(4, list.Count());
        }

        [TestMethod]
        public void ParseListWithComment()
        {
            var conf = ParseConfiguration();

            var list = conf.Get<IEnumerable<EncryptionType>>("libdefaults.commented_enctypes");

            Assert.AreEqual(1, list.Count());
        }

        private static ConfigurationSectionList ParseConfiguration()
        {
            var file = ReadDataFile("Configuration\\krb5.conf");

            return Krb5ConfigurationSerializer.Deserialize(Encoding.Default.GetString(file));
        }

        [TestMethod]
        public void ConfigurationStoresMultipleValuesToSingleKey()
        {
            var config = new ConfigurationSectionList
            {
                { "foo", "bar" }
            };

            Assert.AreEqual("bar", config["foo"]);

            config.Add("foo", "baz");

            var foo = config["foo"];

            Assert.IsInstanceOfType(foo, typeof(IEnumerable<object>));

            var foo2 = foo as IEnumerable<object>;

            Assert.AreEqual(2, foo2.Count());
            Assert.AreEqual("bar", foo2.ElementAt(0));
            Assert.AreEqual("baz", foo2.ElementAt(1));

            config.Remove("foo");

            Assert.IsNull(config["foo"]);
        }
    }
}
