using Kerberos.NET;
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
        private static async Task<KerberosIdentity> GenerateAuthZ()
        {
            var authenticator = new KerberosAuthenticator(new KerberosValidator(new KerberosKey("P@ssw0rd!"))
            {
                ValidateAfterDecrypt = DefaultActions
            });

            var authenticated = await authenticator.Authenticate(Convert.FromBase64String(TicketContainingDelegation));

            Assert.IsNotNull(authenticated);

            var identity = authenticated as KerberosIdentity;

            Assert.IsNotNull(identity);

            return identity;
        }

        private static IEnumerable<T> AssertAllAreRestrictionType<T>(KerberosIdentity identity, AuthorizationDataType type, int expectedCount)
            where T : Restriction
        {
            if (identity.Restrictions.TryGetValue(type, out IEnumerable<Restriction> restrictions))
            {
                Assert.IsNotNull(restrictions);
            }

            Assert.AreEqual(expectedCount, restrictions.Count());

            var typedRestrictions = restrictions.Select(r => r as T).Where(r => r != null);

            Assert.AreEqual(expectedCount, typedRestrictions.Count());

            return typedRestrictions;
        }

        [TestMethod]
        public async Task TestETypeNegotiation()
        {
            var restrictionsSet = AssertAllAreRestrictionType<ETypeNegotiationRestriction>(
                await GenerateAuthZ(),
                AuthorizationDataType.AdETypeNegotiation,
                1
            );

            foreach (var etype in restrictionsSet)
            {
                Assert.IsNotNull(etype);

                Assert.AreEqual(3, etype.ETypes.Count());

                Assert.AreEqual(EncryptionType.AES256_CTS_HMAC_SHA1_96, etype.ETypes.ElementAt(0));
                Assert.AreEqual(EncryptionType.AES128_CTS_HMAC_SHA1_96, etype.ETypes.ElementAt(1));
                Assert.AreEqual(EncryptionType.RC4_HMAC_NT, etype.ETypes.ElementAt(2));
            }
        }

        [TestMethod]
        public async Task TestTokenRestrictions()
        {
            var restrictionsSet = AssertAllAreRestrictionType<KerbAuthDataTokenRestriction>(
                await GenerateAuthZ(),
                AuthorizationDataType.KerbAuthDataTokenRestrictions,
                2
            );

            foreach (var restrictions in restrictionsSet)
            {
                Assert.AreEqual(0, restrictions.RestrictionType);
                Assert.IsNotNull(restrictions.Restriction);
                Assert.AreEqual(IntegrityLevels.High, restrictions.Restriction.TokenIntegrityLevel);
                Assert.AreEqual(TokenTypes.Full, restrictions.Restriction.Flags);
                Assert.IsNotNull(restrictions.Restriction.MachineId);
            }
        }

        [TestMethod]
        public async Task TestKerbLocal()
        {
            var restrictionsSet = AssertAllAreRestrictionType<KerbLocalRestriction>(
                await GenerateAuthZ(),
                AuthorizationDataType.KerbLocal,
                2
            );

            foreach (var local in restrictionsSet)
            {
                Assert.IsNotNull(local.Value);
            }
        }

        [TestMethod]
        public async Task TestApOptions()
        {
            var restrictionsSet = AssertAllAreRestrictionType<KerbApOptionsRestriction>(
                await GenerateAuthZ(),
                AuthorizationDataType.KerbApOptions,
                1
            );

            foreach (var options in restrictionsSet)
            {
                Assert.AreEqual(ApOptions.ChannelBindingSupported, options.Options);
            }
        }

        [TestMethod]
        public async Task TestKerbServiceTarget()
        {
            var restrictionsSet = AssertAllAreRestrictionType<KerbServiceTargetRestriction>(
                await GenerateAuthZ(),
                AuthorizationDataType.KerbServiceTarget,
                1
            );

            foreach (var serviceName in restrictionsSet)
            {
                Assert.AreEqual("host/app.corp.identityintervention.com@CORP.IDENTITYINTERVENTION.COM", serviceName.ServiceName);
            }
        }
    }
}
