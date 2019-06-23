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

            var cred = data.Authenticator
                           .Checksum
                           .Delegation
                           .DelegationTicket
                           .Credential
                           .CredentialPart;

            Assert.IsNotNull(cred);

            Assert.AreEqual(1, cred.Tickets.Count());

            var ticket = cred.Tickets.First();

            Assert.AreEqual("Administrator", ticket.PrincipalName.Names.First());
            Assert.AreEqual("krbtgt/CORP.IDENTITYINTERVENTION.COM", ticket.SName.Names.First());

            Assert.IsNotNull(ticket.Key);
            Assert.IsNotNull(ticket.Key.RawKey);
        }
    }
}
