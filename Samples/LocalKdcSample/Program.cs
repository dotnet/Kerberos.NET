// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Threading.Tasks;
using Kerberos.NET.Client;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Server;

namespace LocalKdcSample
{
    /// <summary>
    /// Demonstrates a server application that hosts a "Local KDC".
    /// </summary>
    /// <remarks>
    /// Normally a Kerberos client must reach off-box to a KDC (a domain controller) to obtain
    /// tickets before it can authenticate to a service. With IAKERB, the client instead tunnels
    /// its AS/TGS exchanges through the target service, and the service forwards them to a KDC.
    ///
    /// In this sample the KDC is not off-box at all - it runs in-process on the server, backed by
    /// a small local account store. So the complete flow is:
    ///
    ///   client (IAKerbInitiator)  -- GSS tokens -->  server (IAKerbAcceptor)
    ///                                                      |
    ///                                                      v
    ///                                             in-proc KdcServer  &lt;->  LocalSecurityStore
    ///
    /// The client never talks to a KDC directly; the server's in-proc KDC does all the work.
    /// </remarks>
    internal static class Program
    {
        private const string UserName = LocalSecurityStore.UserPrincipalName;
        private const string Password = "P@ssw0rd!";

        private static async Task Main()
        {
            var store = new LocalSecurityStore();

            // 1. Stand up the in-process KDC over the local store.
            var kdc = BuildLocalKdc(store);

            // 2. The service hosts an IAKerb acceptor. It owns the service keytab (to decrypt the
            //    final AP-REQ) and a transport that forwards proxied KDC messages to the in-proc KDC.
            var kdcTransport = new InProcessKdcTransport(kdc);
            var serviceKeys = store.GetServiceKeyTable(LocalSecurityStore.ServiceSpn);

            // 3. The client builds an IAKerb initiator for the target service. It produces GSS tokens
            //    instead of talking to a KDC; the server proxies them on its behalf.
            var credential = new KerberosPasswordCredential(UserName, Password);

            Console.WriteLine($"Local KDC realm : {LocalSecurityStore.Realm}");
            Console.WriteLine($"Client identity : {UserName}");
            Console.WriteLine($"Target service  : {LocalSecurityStore.ServiceSpn}");
            Console.WriteLine();

            using (var initiator = new IAKerbInitiator(credential, LocalSecurityStore.ServiceSpn))
            using (var acceptor = new IAKerbAcceptor(kdcTransport, serviceKeys))
            {
                // Kick off the exchange. The initiator yields the first GSS token to send to the server.
                var clientResult = await initiator.InitSecurityContext();

                int roundTrip = 0;

                while (true)
                {
                    roundTrip++;
                    Console.WriteLine($"[round {roundTrip}] client -> server : {clientResult.Token.Length} byte GSS token");

                    // The server feeds the client's token to the acceptor, which forwards any contained
                    // AS/TGS message to the in-proc KDC and returns the response (or, finally, the AP-REP).
                    var serverResult = await acceptor.AcceptSecurityContext(clientResult.Token);

                    if (serverResult.IsComplete)
                    {
                        Console.WriteLine($"[round {roundTrip}] server         : authentication complete");
                        break;
                    }

                    Console.WriteLine($"[round {roundTrip}] server -> client : {serverResult.Token.Value.Length} byte GSS token");

                    // The client consumes the server's response and produces the next token.
                    clientResult = await initiator.InitSecurityContext(serverResult.Token.Value);
                }

                Console.WriteLine();
                Console.WriteLine("=== Result ===");
                Console.WriteLine($"Initiator state : {initiator.State}");
                Console.WriteLine($"Acceptor state  : {acceptor.State}");

                var apReq = acceptor.DecryptedApReq;
                Console.WriteLine($"Authenticated   : {apReq.Authenticator.CName.FullyQualifiedName}");
                Console.WriteLine($"Service (SName) : {apReq.SName.FullyQualifiedName}");
                Console.WriteLine($"Ticket etype    : {apReq.EType}");
            }
        }

        private static KdcServer BuildLocalKdc(LocalSecurityStore store)
        {
            var config = Krb5Config.Kdc();

            var options = new KdcServerOptions
            {
                DefaultRealm = LocalSecurityStore.Realm,
                IsDebug = true,
                Configuration = config,

                // Any realm resolves to the single, locally-backed realm service.
                RealmLocator = _ => new LocalRealmService(store, config)
            };

            return new KdcServer(options);
        }
    }
}
