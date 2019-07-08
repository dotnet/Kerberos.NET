using Kerberos.NET.Asn1;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Diagnostics;
using System.Linq;

namespace Tests.Kerberos.NET.Messages
{
    [TestClass]
    public class AllMessagesTests : BaseTest
    {
        [TestMethod]
        public void TestBitOps()
        {
            var values = new int[] { int.MinValue, int.MaxValue, 0, 123, -23346457, 2342341, -234234, 23456, 123456789 };

            for (var i = 0; i < values.Length; i++)
            {
                var bytes = BitOperation.AsReadOnly(i);

                var newNum = BitOperation.AsInt(bytes.ToArray());

                Assert.AreEqual(i, newNum);
            }
        }

        [TestMethod]
        public void TestParseAllMessagesRoundtrip()
        {
            var allMessages = ReadDataFiles("messages\\");

            foreach (var file in allMessages)
            {
                var key = file.Key.Substring(file.Key.LastIndexOf('\\') + 1);

                Debug.WriteLine(file.Value.HexDump());

                switch (key)
                {
                    case "as-rep":
                        //TestSimpleRoundtrip(key, file.Value, v => KrbAsRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "as-req":
                        TestSimpleRoundtrip(key, file.Value, v => KrbAsReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "as-req-preauth":
                        TestSimpleRoundtrip(key, file.Value, v => KrbAsReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "krb-error-preauth-required":
                        TestSimpleRoundtrip(key, file.Value, v => KrbError.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-rep-testuser-host-app03":
                        //TestSimpleRoundtrip(key, file.Value, v => KrbTgsRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-rep-testuser-host-appservice":
                        //TestSimpleRoundtrip(key, file.Value, v => KrbTgsRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-rep-testuser-krbtgt-renew":
                        //TestSimpleRoundtrip(key, file.Value, v => KrbTgsRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-req-testuser-host-app03":
                        var thing = TestSimpleRoundtrip(key, file.Value, v => KrbTgsReq.Decode(v), t => t.Encode().ToArray());

                        var ap = KrbApChoice.Decode(thing.TgsReq.PaData[0].Value);

                        break;
                    case "tgs-req-testuser-host-appservice":
                        TestSimpleRoundtrip(key, file.Value, v => KrbTgsReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-req-testuser-krbtgt-renew":
                        TestSimpleRoundtrip(key, file.Value, v => KrbTgsReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    default:
                        Assert.Fail(file.Key);
                        break;
                }
            }
        }

        private T TestSimpleRoundtrip<T>(string key, byte[] value, Func<byte[], T> decode, Func<T, byte[]> encode)
        {
            var thing = decode(value);

            var encoded = encode(thing);

            Assert.IsTrue(value.SequenceEqual(encoded), key);

            return thing;
        }
    }
}
