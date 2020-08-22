// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class KrbCredCarrierTests
    {
        [TestMethod]
        public void CreateKrbCredSucceeds()
        {
            KrbCred krbCred = CreateKrbCredential();

            Assert.IsNotNull(krbCred);
            Assert.AreEqual(EncryptionType.NULL, krbCred.EncryptedPart.EType);
            Assert.AreEqual("host/test.com", krbCred.Tickets[0].SName.FullyQualifiedName);
        }

        private static KrbCred CreateKrbCredential()
        {
            var key = new KerberosKey(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96);

            KrbCred krbCred = KrbKdcRep.GenerateWrappedServiceTicket(new ServiceTicketRequest
            {
                Principal = new FakeKerberosPrincipal("test@test.com"),
                ServicePrincipal = new FakeKerberosPrincipal("host/test.com"),
                ServicePrincipalKey = key,
                IncludePac = false,
                RealmName = "test.com",
                Now = DateTimeOffset.UtcNow,
                StartTime = DateTimeOffset.UtcNow,
                EndTime = DateTimeOffset.UtcNow.AddHours(5),
                RenewTill = DateTimeOffset.UtcNow.AddDays(3),
                Flags = TicketFlags.Renewable
            });

            return krbCred;
        }

        [TestMethod]
        public async Task KrbCredImportsAndGets()
        {
            var krbCred = CreateKrbCredential();

            using (var client = new KerberosClient())
            {
                client.ImportCredential(krbCred);

                var serviceTicket = await client.GetServiceTicket("host/test.com");

                Assert.IsNotNull(serviceTicket);
                Assert.IsNotNull(serviceTicket.Authenticator);
                Assert.IsNotNull(serviceTicket.Ticket);
            }
        }

        [TestMethod]
        public async Task KrbCredImportsAndPassesAuthenticatorValidation()
        {
            var krbCred = CreateKrbCredential();

            using (var client = new KerberosClient())
            {
                client.ImportCredential(krbCred);

                var serviceTicket = await client.GetServiceTicket("host/test.com");

                Assert.IsNotNull(serviceTicket);

                var encodedTicket = "Negotiate " + Convert.ToBase64String(serviceTicket.EncodeGssApi().ToArray());

                var authenticator = new KerberosAuthenticator(new KeyTable(new KerberosKey(new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96)));

                var result = await authenticator.Authenticate(encodedTicket);

                Assert.IsNotNull(result);
                Assert.AreEqual("test@test.com", result.Name);
            }
        }
    }
}
