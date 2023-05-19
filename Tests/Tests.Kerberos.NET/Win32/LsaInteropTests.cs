// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class LsaInteropTests
    {
        private const string RequestedSpn = "host/test.com";

        private static readonly KerberosKey Key = new(key: new byte[16], etype: EncryptionType.AES128_CTS_HMAC_SHA1_96);

        private static KrbCred CreateKrbCredential()
        {
            KrbCred krbCred = KrbKdcRep.GenerateWrappedServiceTicket(new ServiceTicketRequest
            {
                Principal = new FakeKerberosPrincipal("test@test.com"),
                ServicePrincipal = new FakeKerberosPrincipal(RequestedSpn),
                ServicePrincipalKey = Key,
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
        public void LsaConnectUntrusted()
        {
            using (var interop = LsaInterop.Connect())
            {
                Assert.IsNotNull(interop);
            }
        }

        [TestMethod]
        public void LsaImportCredential()
        {
            var cred = CreateKrbCredential();

            using (var interop = LsaInterop.Connect())
            {
                Assert.IsNotNull(interop);

                interop.ImportCredential(cred);
            }
        }

        [TestMethod]
        public void LsaImportSspiIsc()
        {
            var cred = CreateKrbCredential();

            using (var interop = LsaInterop.Connect())
            {
                Assert.IsNotNull(interop);

                interop.ImportCredential(cred);

                RetrieveAndVerifyTicket();
            }
        }

        [TestMethod]
        public void LsaLogonUserImportSspiIsc_NoPurge()
        {
            var cred = CreateKrbCredential();

            using (var interop = LsaInterop.Connect())
            {
                Assert.IsNotNull(interop);

                interop.LogonUser();

                interop.ImportCredential(cred);

                RetrieveAndVerifyTicket();
            }
        }

        [TestMethod]
        public void LsaLogonUserImportSspiIsc_Purge()
        {
            var cred = CreateKrbCredential();

            using (var interop = LsaInterop.Connect())
            {
                Assert.IsNotNull(interop);

                interop.PurgeTicketCache();

                interop.LogonUser();

                interop.ImportCredential(cred);

                RetrieveAndVerifyTicket();
            }
        }

        [TestMethod]
        public async Task LsaLogonUserImportUseCache()
        {
            var cred = CreateKrbCredential();
            var config = Krb5Config.Default();

            using (var interop = LsaInterop.Connect())
            {
                Assert.IsNotNull(interop);

                interop.LogonUser();

                interop.ImportCredential(cred);

                using (var client = new KerberosClient(config) { Cache = new LsaCredentialCache(config, interop) })
                {
                    var ticket = await client.GetServiceTicket(RequestedSpn);

                    Assert.IsNotNull(ticket);
                }
            }
        }

        // This test requires Windows TCB to operate which only happens when running as SYSTEM
        // As such this is a manual test that should only be when the environment is set up correctly
        //
        // [TestMethod]
        public static void LsaConnectTrusted()
        {
            using (var interop = LsaInterop.RegisterLogonProcess("KerbNetTests"))
            {
                Assert.IsNotNull(interop);
            }
        }

        private static void RetrieveAndVerifyTicket()
        {
            using (var context = new SspiContext(RequestedSpn))
            {
                var ticket = context.RequestToken();

                var token = MessageParser.ParseKerberos(ticket);

                var decryptedToken = token.DecryptApReq(new KeyTable(Key));

                Assert.AreEqual("test@test.com", decryptedToken.Ticket.CName.FullyQualifiedName);
                Assert.AreEqual("test.com", decryptedToken.Ticket.CRealm);
            }
        }
    }
}
