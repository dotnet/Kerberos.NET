using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;

namespace Tests.Kerberos.NET.Messages
{
    [TestClass]
    public class AllMessagesTests : BaseTest
    {
        [TestMethod]
        public void TestParseAllMessagesRoundtrip()
        {
            var allMessages = ReadDataFiles("messages\\");

            foreach (var file in allMessages)
            {
                var key = file.Key.Substring(file.Key.LastIndexOf('\\') + 1);

                switch (key)
                {
                    case "as-rep":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "as-req":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "as-req-preauth":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "krb-error-preauth-required":
                        TestSimpleRoundtrip(key, file.Value, v => KrbError.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-rep-testuser-host-app03":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-rep-testuser-host-appservice":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-rep-testuser-krbtgt-renew":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcRep.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-req-testuser-host-app03":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-req-testuser-host-appservice":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    case "tgs-req-testuser-krbtgt-renew":
                        TestSimpleRoundtrip(key, file.Value, v => KrbKdcReq.Decode(v), t => t.Encode().ToArray());
                        break;
                    default:
                        Assert.Fail(file.Key);
                        break;
                }
            }
        }

        private void TestSimpleRoundtrip<T>(string key, byte[] value, Func<byte[], T> decode, Func<T, byte[]> encode)
        {
            var thing = decode(value);

            var encoded = encode(thing);

            Assert.IsTrue(value.SequenceEqual(encoded), key);
        }
    }
}
