using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
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

            Assert.AreEqual("Administrator", ticket.PName.Value.Name.First());
            Assert.AreEqual("krbtgt/CORP.IDENTITYINTERVENTION.COM", ticket.SName.Value.FullyQualifiedName);

            Assert.IsNotNull(ticket.Key);
            Assert.IsNotNull(ticket.Key.KeyValue);
        }
    }
}
