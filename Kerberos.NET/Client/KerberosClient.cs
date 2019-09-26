﻿using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    public class KerberosClient : IDisposable
    {
        // - transport -> TCP/UDP/injected transport handler
        //
        // - KDC resolution -> specify DC name or use DNS resolution?
        //                  -> DC resolver tries DC by locator instead?
        //
        // - authenticate -> as-rep => TGT
        //                   -> request PAC?
        //                   -> include pre-auth by default?
        //                   -> automatically retry with pre-auth added?
        //                   -> request ticket for self to get local authz?
        //                   -> cache TGT/cache service ticket?

        public KerberosClient(string kdc = null)
            : this(new UdpKerberosTransport(kdc),
                   new TcpKerberosTransport(kdc))
        {
        }

        private const AuthenticationOptions DefaultAuthentication =
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        private const ApOptions DefaultApOptions = 0;

        private readonly KerberosTransportSelector transport;

        public KerberosClient(params IKerberosTransport[] transports)
        {
            transport = new KerberosTransportSelector(transports);
        }

        public IEnumerable<IKerberosTransport> Transports => transport.Transports;

        public KrbKdcRep TicketGrantingTicket { get; private set; }

        public KrbEncryptionKey TgtSessionKey { get; private set; }

        public AuthenticationOptions AuthenticationOptions { get; set; } = DefaultAuthentication;

        public KdcOptions KdcOptions { get => (KdcOptions)(AuthenticationOptions & ~AuthenticationOptions.AllAuthentication); }

        public async Task Authenticate(KerberosCredential credential)
        {
            credential.Validate();

            int preauthAttempts = 0;

            AuthenticationOptions &= ~AuthenticationOptions.PreAuthenticate;

            do
            {
                try
                {
                    await RequestTgt(credential);
                    break;
                }
                catch (KerberosProtocolException pex)
                {
                    if (++preauthAttempts > 3 || pex?.Error?.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        throw;
                    }

                    credential.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());

                    AuthenticationOptions |= AuthenticationOptions.PreAuthenticate;
                }
            }
            while (true);
        }

        public async Task<KrbApReq> GetServiceTicket(
            string spn,
            ApOptions options = DefaultApOptions,
            KrbTicket u2uServerTicket = null,
            string s4u = null
        )
        {
            CopyTgt(out KrbEncryptionKey sessionKey, out KrbKdcRep tgt);

            var kdcOptions = KdcOptions;

            if (u2uServerTicket != null)
            {
                kdcOptions |= KdcOptions.EncTktInSkey;
            }

            if (!string.IsNullOrWhiteSpace(s4u))
            {
                kdcOptions |= KdcOptions.CNameInAdditionalTicket;
            }

            var tgs = KrbTgsReq.CreateTgsReq(spn, sessionKey, tgt, kdcOptions, u2uServerTicket, s4u);

            var encodedTgs = tgs.EncodeApplication();

            var tgsRep = await transport.SendMessage<KrbTgsRep>(
                tgs.Body.Realm,
                encodedTgs
            );

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                sessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            var authenticatorKey = encKdcRepPart.Key.AsKey();

            return KrbApReq.CreateApReq(tgsRep, authenticatorKey, options);
        }

        private readonly object _syncTicket = new object();

        private void CopyTgt(out KrbEncryptionKey sessionKey, out KrbKdcRep tgt)
        {
            lock (_syncTicket)
            {
                if (TgtSessionKey == null || TicketGrantingTicket == null)
                {
                    throw new InvalidOperationException("Cannot request a service ticket until a user is authenticated");
                }

                sessionKey = KrbEncryptionKey.Decode(TgtSessionKey.Encode().AsMemory());

                tgt = KrbKdcRep.Decode(TicketGrantingTicket.Encode().AsMemory());
            }
        }

        public async Task RenewTicket()
        {
            CopyTgt(out KrbEncryptionKey sessionKey, out KrbKdcRep tgt);

            var tgs = KrbTgsReq.CreateTgsReq("krbtgt", sessionKey, tgt, KdcOptions);

            var encodedTgs = tgs.EncodeApplication();

            var tgsRep = await transport.SendMessage<KrbTgsRep>(
                tgs.Body.Realm,
                encodedTgs
            );

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                sessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            CacheTgt(tgsRep, encKdcRepPart);
        }

        private async Task RequestTgt(KerberosCredential credential)
        {
            var asReq = KrbAsReq.CreateAsReq(credential, AuthenticationOptions).EncodeApplication();

            var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);

            var decrypted = DecryptAsRep(asRep, credential);

            CacheTgt(asRep, decrypted);
        }

        private void CacheTgt(KrbKdcRep kdcRep, KrbEncKdcRepPart decrypted)
        {
            // not the most sophisticated of caches

            lock (_syncTicket)
            {
                TicketGrantingTicket = kdcRep;
                TgtSessionKey = decrypted.Key;
            }
        }

        private static KrbEncAsRepPart DecryptAsRep(KrbKdcRep asRep, KerberosCredential credential)
        {
            var key = credential.CreateKey();

            return asRep.EncPart.Decrypt(key, KeyUsage.EncAsRepPart, d => KrbEncAsRepPart.DecodeApplication(d));
        }

        public void Dispose()
        {
            if (transport != null)
            {
                transport.Dispose();
            }
        }
    }
}
