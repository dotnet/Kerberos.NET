using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Linq;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbtgtTests : BaseTest
    {
        private static readonly byte[] key = new byte[]
        {
            0xef, 0x74, 0x22, 0xcb, 0x49, 0xe2, 0xf5, 0xb0, 0x92, 0x92, 0xcb, 0xd8, 0x25, 0xc2, 0x95, 0x24,
            0x9f, 0x2a, 0x31, 0x46, 0x5d, 0xc9, 0xab, 0x4a, 0x30, 0x80, 0xed, 0xf3, 0x16, 0x8a, 0x88, 0x57
        };

        [TestMethod]
        public void KrbtgtDecode()
        {
            var krbtgtKey = new KerberosKey(key: key);
            var longUserTermKey = new KerberosKey("P@ssw0rd!", salt: "CORP.IDENTITYINTERVENTION.COMtestuser");

            var krbAsRepBytes = ReadDataFile("messages\\as-rep").Skip(4).ToArray();

            var asRep = new KrbAsRep().DecodeAsApplication(krbAsRepBytes);

            var encPart = asRep.EncPart.Decrypt(longUserTermKey, KeyUsage.EncAsRepPart, b => KrbEncAsRepPart.DecodeApplication(b));

            Assert.IsNotNull(encPart);

            var encTicket = asRep.Ticket.EncryptedPart;

            var krbtgt = encTicket.Decrypt(krbtgtKey, KeyUsage.Ticket, bytes => new KrbEncTicketPart().DecodeAsApplication(bytes));

            Assert.IsNotNull(krbtgt);
        }
    }
}
