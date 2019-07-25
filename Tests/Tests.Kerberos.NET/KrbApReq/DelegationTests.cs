using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DelegationTests : BaseTest
    {
        [TestMethod]
        public async Task TestDelegationRetrieval()
        {
            var validator = new KerberosValidator(new KerberosKey("P@ssw0rd!")) { ValidateAfterDecrypt = DefaultActions };

            var data = await validator.Validate(Convert.FromBase64String(TicketContainingDelegation));

            Assert.IsNotNull(data);

            var cred = data.DelegationTicket;

            Assert.IsNotNull(cred);

            Assert.AreEqual(1, cred.TicketInfo.Count());

            var ticket = cred.TicketInfo.First();

            Assert.AreEqual("Administrator", ticket.PName.Name.First());
            Assert.AreEqual("krbtgt/CORP.IDENTITYINTERVENTION.COM", ticket.SName.FullyQualifiedName);

            Assert.IsNotNull(ticket.Key);
            Assert.IsNotNull(ticket.Key.KeyValue);
        }

        [TestMethod]
        public void TestCredPartRoundtrip()
        {
            KrbEncKrbCredPart part = new KrbEncKrbCredPart
            {
                Nonce = 123,
                RAddress = new KrbHostAddress
                {
                    Address = Encoding.ASCII.GetBytes("blaaaaaaaah"),
                    AddressType = AddressType.NetBios
                },
                SAddress = new KrbHostAddress
                {
                    Address = Encoding.ASCII.GetBytes("server"),
                    AddressType = AddressType.NetBios
                },
                Timestamp = DateTimeOffset.UtcNow,
                USec = 123,
                TicketInfo = new[] {
                    new KrbCredInfo {
                        AuthorizationData = new KrbAuthorizationData[] {
                            new KrbAuthorizationData {
                                Data = new byte[0],
                                Type = AuthorizationDataType.AdAndOr
                            }
                        },
                        AuthTime = DateTimeOffset.UtcNow,
                        EndTime = DateTimeOffset.UtcNow,
                        RenewTill = DateTimeOffset.UtcNow,
                        Flags = TicketFlags.Anonymous,
                        Key = KrbEncryptionKey.Generate(EncryptionType.AES128_CTS_HMAC_SHA1_96),
                        PName = new KrbPrincipalName {
                            Name = new [] { "pname" },
                            Type = PrincipalNameType.NT_ENTERPRISE
                        },
                        Realm = "realm.com",
                        SName = new KrbPrincipalName {
                            Name = new [] { "server" },
                            Type = PrincipalNameType.NT_ENTERPRISE
                        },
                        SRealm = "srealm.com",
                        StartTime = DateTimeOffset.UtcNow
                    }
                }
            };

            var encoded = part.EncodeApplication();

            var decoded = KrbEncKrbCredPart.DecodeApplication(encoded);

            Assert.IsNotNull(decoded);

            Assert.AreEqual(part.Nonce, decoded.Nonce);
            Assert.AreEqual(1, part.TicketInfo.Length);
        }
    }
}
