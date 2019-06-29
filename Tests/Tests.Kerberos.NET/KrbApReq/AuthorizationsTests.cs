using Kerberos.NET;
using Kerberos.NET.Asn1.Entities;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class AuthorizationsTests : BaseTest
    {
        private static async Task<IDictionary<AuthorizationDataValueType, AuthorizationDataElement>> GenerateAuthZ()
        {
            var validator = new KerberosValidator(new KerberosKey("P@ssw0rd!"))
            {
                ValidateAfterDecrypt = DefaultActions
            };

            var data = await validator.Validate(Convert.FromBase64String(TicketContainingDelegation));

            Assert.IsNotNull(data);


            return new Dictionary<AuthorizationDataValueType, AuthorizationDataElement>();  //data.Authenticator.AuthorizationMap;
        }

        [TestMethod]
        public async Task TestETypeNegotiation()
        {
            var authz = await GenerateAuthZ();

            var etype = (NegotiatedETypes)authz[AuthorizationDataValueType.AD_ETYPE_NEGOTIATION];

            Assert.IsNotNull(etype);

            Assert.AreEqual(3, etype.ETypes.Count());

            Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, etype.ETypes.ElementAt(0));
            Assert.AreEqual(EncryptionType.AES128_CTS_HMAC_SHA1_96, etype.ETypes.ElementAt(1));
            Assert.AreEqual(EncryptionType.RC4_HMAC_NT, etype.ETypes.ElementAt(2));
        }

        [TestMethod]
        public async Task TestTokenRestrictions()
        {
            var authz = await GenerateAuthZ();

            var restrictions = (RestrictionEntry)authz[AuthorizationDataValueType.KERB_AUTH_DATA_TOKEN_RESTRICTIONS];

            Assert.AreEqual(0, restrictions.RestrictionType);
            Assert.IsNotNull(restrictions.Restriction);
            Assert.AreEqual(IntegrityLevels.High, restrictions.Restriction.TokenIntegrityLevel);
            Assert.AreEqual(TokenTypes.Full, restrictions.Restriction.Flags);
            Assert.IsNotNull(restrictions.Restriction.MachineId);
        }

        [TestMethod]
        public async Task TestKerbLocal()
        {
            var authz = await GenerateAuthZ();

            var local = (KerbLocal)authz[AuthorizationDataValueType.KERB_LOCAL];

            Assert.IsNotNull(local.Value);
        }

        [TestMethod]
        public async Task TestApOptions()
        {
            var authz = await GenerateAuthZ();

            var options = (KerbApOptions)authz[AuthorizationDataValueType.KERB_AP_OPTIONS];

            Assert.AreEqual(ApOptions.CHANNEL_BINDING_SUPPORTED, options.Options);
        }

        [TestMethod]
        public async Task TestKerbServiceTarget()
        {
            var authz = await GenerateAuthZ();

            var serviceName = (KerbServiceName)authz[AuthorizationDataValueType.KERB_SERVICE_TARGET];

            Assert.AreEqual("host/app.corp.identityintervention.com@CORP.IDENTITYINTERVENTION.COM", serviceName.ServiceName);
        }
    }
}
