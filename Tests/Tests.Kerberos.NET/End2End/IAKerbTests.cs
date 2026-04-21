// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET;
using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Server;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class IAKerbTests : KdcListenerTestBase
    {
        private static KeyTable CreateServiceKeyTable()
        {
            return new KeyTable(
                new KerberosKey(
                    FakeAdminAtCorpPassword,
                    principalName: new PrincipalName(
                        PrincipalNameType.NT_PRINCIPAL,
                        "CORP.IDENTITYINTERVENTION.com",
                        new[] { FakeAppServiceSpn }
                    ),
                    saltType: SaltType.ActiveDirectoryUser
                )
            );
        }

        [TestMethod]
        public async Task IAKerb_EndToEnd_PasswordCredential()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                var credential = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);

                using (var initiator = new IAKerbInitiator(credential, FakeAppServiceSpn))
                {
                    var kdcTransport = new InMemoryTransport(listener);
                    var serviceKeys = CreateServiceKeyTable();

                    using (var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys))
                    {
                        var result = await initiator.InitSecurityContext();

                        Assert.IsTrue(result.ContinueNeeded, "First call should require continuation");
                        Assert.IsTrue(result.Token.Length > 0, "First token should not be empty");

                        while (true)
                        {
                            var serverResult = await acceptor.AcceptSecurityContext(result.Token);

                            if (serverResult.IsComplete)
                            {
                                Assert.AreEqual(IAKerbAcceptorState.Complete, acceptor.State);
                                Assert.IsNotNull(serverResult.DecryptedApReq);
                                break;
                            }

                            Assert.IsTrue(serverResult.Token.HasValue, "Server should return a token during proxy phase");

                            result = await initiator.InitSecurityContext(serverResult.Token.Value);
                        }

                        Assert.AreEqual(IAKerbInitiatorState.Complete, initiator.State);
                        Assert.AreEqual(IAKerbAcceptorState.Complete, acceptor.State);
                        Assert.IsNotNull(initiator.SessionContext);
                        Assert.IsNotNull(acceptor.DecryptedApReq);
                    }
                }
            }
        }

        [TestMethod]
        public async Task IAKerb_EndToEnd_ValidatesFinishedChecksum()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                var credential = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);

                using (var initiator = new IAKerbInitiator(credential, FakeAppServiceSpn))
                {
                    var kdcTransport = new InMemoryTransport(listener);
                    var serviceKeys = CreateServiceKeyTable();

                    using (var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys))
                    {
                        var result = await initiator.InitSecurityContext();

                        while (true)
                        {
                            var serverResult = await acceptor.AcceptSecurityContext(result.Token);

                            if (serverResult.IsComplete)
                            {
                                break;
                            }

                            result = await initiator.InitSecurityContext(serverResult.Token.Value);
                        }

                        // If we get here without exception, the FINISHED checksum was valid
                        Assert.AreEqual(IAKerbAcceptorState.Complete, acceptor.State);
                    }
                }
            }
        }

        [TestMethod]
        public async Task IAKerb_EndToEnd_MultipleRoundTrips()
        {
            // This test verifies that the IAKerb exchange handles the multiple
            // round trips required for pre-authentication (AS exchange) and TGS exchange
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                var credential = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);

                using (var initiator = new IAKerbInitiator(credential, FakeAppServiceSpn))
                {
                    var kdcTransport = new InMemoryTransport(listener);
                    var serviceKeys = CreateServiceKeyTable();

                    using (var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys))
                    {
                        int roundTrips = 0;
                        var result = await initiator.InitSecurityContext();

                        while (true)
                        {
                            roundTrips++;
                            var serverResult = await acceptor.AcceptSecurityContext(result.Token);

                            if (serverResult.IsComplete)
                            {
                                break;
                            }

                            result = await initiator.InitSecurityContext(serverResult.Token.Value);
                        }

                        // Pre-auth typically requires at least 2 round trips:
                        // 1. AS-REQ -> KRB-ERROR (pre-auth required)
                        // 2. AS-REQ (with pre-auth) -> AS-REP
                        // Plus 1 for TGS-REQ -> TGS-REP
                        // Plus 1 for the final AP-REQ
                        Assert.IsTrue(roundTrips >= 2, $"Expected at least 2 round trips, got {roundTrips}");
                        Assert.AreEqual(IAKerbInitiatorState.Complete, initiator.State);
                    }
                }
            }
        }

        [TestMethod]
        public async Task IAKerb_InitiatorState_Transitions()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                var credential = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);

                using (var initiator = new IAKerbInitiator(credential, FakeAppServiceSpn))
                {
                    Assert.AreEqual(IAKerbInitiatorState.NotStarted, initiator.State);

                    var kdcTransport = new InMemoryTransport(listener);
                    var serviceKeys = CreateServiceKeyTable();

                    using (var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys))
                    {
                        var result = await initiator.InitSecurityContext();
                        Assert.AreEqual(IAKerbInitiatorState.InProgress, initiator.State);

                        while (true)
                        {
                            var serverResult = await acceptor.AcceptSecurityContext(result.Token);

                            if (serverResult.IsComplete)
                            {
                                break;
                            }

                            result = await initiator.InitSecurityContext(serverResult.Token.Value);
                        }

                        Assert.AreEqual(IAKerbInitiatorState.Complete, initiator.State);
                    }
                }
            }
        }

        [TestMethod]
        public async Task IAKerb_AcceptorState_Transitions()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                var credential = new KerberosPasswordCredential(AdminAtCorpUserName, FakeAdminAtCorpPassword);

                using (var initiator = new IAKerbInitiator(credential, FakeAppServiceSpn))
                {
                    var kdcTransport = new InMemoryTransport(listener);
                    var serviceKeys = CreateServiceKeyTable();

                    using (var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys))
                    {
                        Assert.AreEqual(IAKerbAcceptorState.WaitingForToken, acceptor.State);

                        var result = await initiator.InitSecurityContext();
                        var serverResult = await acceptor.AcceptSecurityContext(result.Token);

                        Assert.AreEqual(IAKerbAcceptorState.Proxying, acceptor.State);

                        while (!serverResult.IsComplete)
                        {
                            result = await initiator.InitSecurityContext(serverResult.Token.Value);
                            serverResult = await acceptor.AcceptSecurityContext(result.Token);
                        }

                        Assert.AreEqual(IAKerbAcceptorState.Complete, acceptor.State);
                    }
                }
            }
        }
    }
}
