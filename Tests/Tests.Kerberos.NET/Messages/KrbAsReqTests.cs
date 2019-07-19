using Kerberos.NET.Asn1;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text;

namespace Tests.Kerberos.NET.Messages
{
    [TestClass]
    public class KrbAsReqTests : BaseTest
    {
        [TestMethod]
        public void TestAsReqRoundtripParse()
        {
            var creds = new KerberosPasswordCredential("sdfsdfsdf", "sdfsdfsdf", "sdfsdfsdf");

            var asReq = KrbAsReq.CreateAsReq(creds, AuthenticationOptions.AllAuthentication);

            var encoded = asReq.EncodeAsApplication();

            var decoded = KrbAsReq.DecodeAsApplication(encoded);

            Assert.IsNotNull(decoded);
        }

        [TestMethod]
        public void TestParseAsReqApplicationMessage()
        {
            var asReqBin = ReadDataFile("messages\\as-req").Skip(4).ToArray();
            
            var asReq = KrbAsReq.DecodeAsApplication(asReqBin);

            Assert.IsNotNull(asReq);

            var addr = asReq.AsReq.Body.Addresses[0].DecodeAddress();

            Assert.IsNotNull(addr);
            Assert.AreEqual("APP03           ", addr);
        }

        [TestMethod]
        public void TestDecryptAsReqApplicationMessage()
        {
            var asReqBin = ReadDataFile("messages\\as-req-preauth").Skip(4).ToArray();

            var asReq = KrbAsReq.DecodeAsApplication(asReqBin);

            Assert.IsNotNull(asReq);

            KerberosKey key = CreateKey();

            var ts = asReq.AsReq.DecryptTimestamp(key);

            Assert.AreEqual(636985444450060358L, ts.Ticks);
        }

        private static KerberosKey CreateKey()
        {
            var principalName = new PrincipalName(PrincipalNameType.NT_PRINCIPAL, "CORP.IDENTITYINTERVENTION.COM", new[] { "testuser" });
            var host = "";

            var key = new KerberosKey(
                "P@ssw0rd!", 
                principalName: principalName, 
                host: host, 
                saltType: SaltType.ActiveDirectoryUser, 
                etype: EncryptionType.AES256_CTS_HMAC_SHA1_96
            );

            return key;
        }

        [TestMethod]
        public void TestGenerateAsReqApplicationMessage()
        {
            var ts = new KrbPaEncTsEnc
            {
                PaTimestamp = new DateTimeOffset(636973454050000000, TimeSpan.Zero),
                PaUSec = 868835
            };

            var key = CreateKey();

            var tsEncoded = ts.Encode();

            KrbEncryptedData encData = KrbEncryptedData.Encrypt(
                tsEncoded.AsMemory(),
                key,
                KeyUsage.PaEncTs
            );

            Assert.IsTrue(tsEncoded.SequenceEqual(encData.Decrypt(key, KeyUsage.PaEncTs, d => KrbPaEncTsEnc.Decode(d)).Encode()));

            var asreq = new KrbAsReq()
            {
                AsReq = new KrbKdcReq()
                {
                    MessageType = MessageType.KRB_AP_REQ,
                    ProtocolVersionNumber = 5,
                    Body = new KrbKdcReqBody
                    {
                        Addresses = new[] {
                            new KrbHostAddress {
                                AddressType = AddressType.NetBios,
                                Address = Encoding.ASCII.GetBytes("APP03           ")
                            }
                        },
                        CName = new KrbPrincipalName
                        {
                            Name = new[] { "testuser@corp.identityintervention.com" },
                            Type = PrincipalNameType.NT_ENTERPRISE
                        },
                        EType = new[] {
                            EncryptionType.AES256_CTS_HMAC_SHA1_96,
                            EncryptionType.AES128_CTS_HMAC_SHA1_96,
                            EncryptionType.RC4_HMAC_NT,
                            EncryptionType.RC4_HMAC_NT_EXP,
                            EncryptionType.RC4_HMAC_OLD_EXP,
                            EncryptionType.DES_CBC_MD5
                        },
                        KdcOptions = KdcOptions.RenewableOk | KdcOptions.Canonicalize | KdcOptions.Renewable | KdcOptions.Forwardable,
                        Nonce = 717695934,
                        RTime = new DateTimeOffset(642720196850000000L, TimeSpan.Zero),
                        Realm = "CORP.IDENTITYINTERVENTION.COM",
                        SName = new KrbPrincipalName
                        {
                            Type = PrincipalNameType.NT_SRV_INST,
                            Name = new[] { "krbtgt", "CORP.IDENTITYINTERVENTION.COM" }
                        },
                        Till = new DateTimeOffset(642720196850000000L, TimeSpan.Zero)
                    },
                    PaData = new[] {
                        new KrbPaData {
                            Type = PaDataType.PA_ENC_TIMESTAMP,
                            Value = new ReadOnlyMemory<byte>(encData.Encode().ToArray())
                        },
                        new KrbPaData {
                            Type = PaDataType.PA_PAC_REQUEST,
                            Value = new ReadOnlyMemory<byte>(new KrbPaPacRequest { IncludePac = true }.Encode().ToArray())
                        }
                    }
                }
            };

            var encodedAsReq = asreq.Encode().ToArray();

            var roundtrip = KrbAsReq.Decode(encodedAsReq);

            Assert.IsNotNull(roundtrip);
        }
    }
}
