using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DecryptedMessageTests
    {
        [TestMethod]
        public void DecryptedApReq_ctor()
        {
            var asreq = new DecryptedKrbApReq(new KrbApReq { });

            Assert.IsNotNull(asreq);
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException))]
        public void DecryptedApReq_NullToken()
        {
            Assert.IsNull(new DecryptedKrbApReq(null));
        }

        [TestMethod]
        public void DecryptedApRep_ctor()
        {
            var asrep = new DecryptedKrbApRep(new KrbApRep { });

            Assert.IsNotNull(asrep);
        }

        [TestMethod, ExpectedException(typeof(ArgumentNullException))]
        public void DecryptedApRep_NullToken()
        {
            Assert.IsNull(new DecryptedKrbApRep(null));
        }

        [TestMethod, ExpectedException(typeof(NotSupportedException))]
        public void DecryptedApRep_Decrypt_Keytab()
        {
            new DecryptedKrbApRep(new KrbApRep { }).Decrypt(new KeyTable());
        }
    }
}
