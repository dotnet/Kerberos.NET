using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using System;
using System.Collections.Generic;
using System.Threading;
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

            Cache = new MemoryTicketCache(null);
        }

        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();

        public IEnumerable<IKerberosTransport> Transports => transport.Transports;

        private ITicketCache ticketCache;

        public ITicketCache Cache
        {
            get => ticketCache;
            set => ticketCache = value ?? throw new InvalidOperationException("Cache cannot be null");
        }

        public bool CacheServiceTickets { get; set; }

        public AuthenticationOptions AuthenticationOptions { get; set; } = DefaultAuthentication;

        public KdcOptions KdcOptions { get => (KdcOptions)(AuthenticationOptions & ~AuthenticationOptions.AllAuthentication); }

        public string DefaultDomain { get; private set; }

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
            cancellation.Token.ThrowIfCancellationRequested();

            var tgtEntry = await CopyTgt($"krbtgt/{DefaultDomain}");

            var kdcOptions = KdcOptions;

            if (u2uServerTicket != null)
            {
                kdcOptions |= KdcOptions.EncTktInSkey;
            }

            if (!string.IsNullOrWhiteSpace(s4u))
            {
                kdcOptions |= KdcOptions.CNameInAdditionalTicket;
            }

            var serviceTicketCacheEntry = await Cache.Get<KerberosClientCacheEntry>(spn);

            if (serviceTicketCacheEntry.Ticket == null)
            {
                serviceTicketCacheEntry = await RequestTgs(
                    spn,
                    tgtEntry,
                    kdcOptions,
                    s4u,
                    u2uServerTicket
                );
            }

            var encKdcRepPart = serviceTicketCacheEntry.Ticket.EncPart.Decrypt(
                serviceTicketCacheEntry.SessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            return KrbApReq.CreateApReq(serviceTicketCacheEntry.Ticket, encKdcRepPart.Key.AsKey(), options);
        }

        private async Task<KerberosClientCacheEntry> RequestTgs(
            string spn,
            KerberosClientCacheEntry tgtEntry,
            KdcOptions kdcOptions,
            string s4u,
            KrbTicket u2uServerTicket
        )
        {
            var tgsReq = KrbTgsReq.CreateTgsReq(
                spn,
                tgtEntry.SessionKey,
                tgtEntry.Ticket,
                kdcOptions,
                out KrbEncryptionKey subkey,
                u2uServerTicket,
                s4u
            );

            var encodedTgs = tgsReq.EncodeApplication();

            cancellation.Token.ThrowIfCancellationRequested();

            var tgsRep = await transport.SendMessage<KrbTgsRep>(
                tgsReq.Body.Realm,
                encodedTgs,
                cancellation.Token
            );

            var entry = new KerberosClientCacheEntry
            {
                Ticket = tgsRep,
                SessionKey = subkey
            };

            if (CacheServiceTickets)
            {
                await Cache.Add(new TicketCacheEntry
                {
                    Key = spn,
                    Expires = tgsReq.Body.Till,
                    Value = entry
                });
            }

            return entry;
        }

        private readonly object _syncTicket = new object();

        private async Task<KerberosClientCacheEntry> CopyTgt(string spn)
        {
            var entry = await Cache.Get<KerberosClientCacheEntry>(spn);

            lock (_syncTicket)
            {
                if (entry.Ticket == null)
                {
                    throw new InvalidOperationException("Cannot request a service ticket until a user is authenticated");
                }

                entry.SessionKey = KrbEncryptionKey.Decode(entry.SessionKey.Encode().AsMemory());
                entry.Ticket = KrbKdcRep.Decode(entry.Ticket.Encode().AsMemory());
            }

            return entry;
        }

        public async Task RenewTicket()
        {
            var entry = await CopyTgt($"krbtgt/{DefaultDomain}");

            var tgs = KrbTgsReq.CreateTgsReq("krbtgt", entry.SessionKey, entry.Ticket, KdcOptions, out KrbEncryptionKey subkey);

            var encodedTgs = tgs.EncodeApplication();

            var tgsRep = await transport.SendMessage<KrbTgsRep>(
                tgs.Body.Realm,
                encodedTgs
            );

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                subkey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            await Cache.Add(new TicketCacheEntry
            {
                Key = tgsRep.Ticket.SName.FullyQualifiedName,
                Expires = encKdcRepPart.RenewTill ?? encKdcRepPart.EndTime,
                Value = new KerberosClientCacheEntry
                {
                    SessionKey = encKdcRepPart.Key,
                    Ticket = tgsRep
                }
            });
        }

        private async Task RequestTgt(KerberosCredential credential)
        {
            var asReq = KrbAsReq.CreateAsReq(credential, AuthenticationOptions).EncodeApplication();

            var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);

            var decrypted = DecryptAsRep(asRep, credential);

            DefaultDomain = credential.Domain;

            await Cache.Add(new TicketCacheEntry
            {
                Key = asRep.Ticket.SName.FullyQualifiedName,
                Expires = decrypted.RenewTill ?? decrypted.EndTime,
                Value = new KerberosClientCacheEntry
                {
                    SessionKey = decrypted.Key,
                    Ticket = asRep
                }
            });
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

            cancellation.Dispose();
        }
    }
}
