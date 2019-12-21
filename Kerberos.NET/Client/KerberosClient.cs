using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    public class KerberosClient : IDisposable
    {
        // - transport -> TCP/UDP/injected transport handler
        //
        // - KDC resolution -> specify DC name or use DNS resolution?
        //                  -> DC resolver tries DC by locater instead?
        //
        // - authenticate -> as-rep => TGT
        //                   -> request PAC?
        //                   -> include pre-auth by default?
        //                   -> automatically retry with pre-auth added?
        //                   -> request ticket for self to get local authz?
        //                   -> cache TGT/cache service ticket?

        public KerberosClient(string kdc = null, ILoggerFactory logger = null)
            : this(logger, CreateTransports(kdc, logger))
        {
        }

        private static IKerberosTransport[] CreateTransports(string kdc, ILoggerFactory logger)
        {
            return new IKerberosTransport[]
            {
                new UdpKerberosTransport(kdc),
                new TcpKerberosTransport(logger, kdc)
            };
        }

        private const AuthenticationOptions DefaultAuthentication =
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        private const ApOptions DefaultApOptions = 0;

        private readonly KerberosTransportSelector transport;
        private readonly ILogger<KerberosClient> logger;
        private readonly IDisposable clientLoggingScope;

        public KerberosClient(ILoggerFactory logger = null, params IKerberosTransport[] transports)
        {
            this.logger = logger.CreateLoggerSafe<KerberosClient>();
            this.clientLoggingScope = this.logger.BeginScope("KerberosClient");

            transport = new KerberosTransportSelector(transports);

            Cache = new MemoryTicketCache(logger);
        }

        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();

        public IEnumerable<IKerberosTransport> Transports => transport.Transports;

        private ITicketCache ticketCache;

        public ITicketCache Cache
        {
            get => ticketCache;
            set => ticketCache = value ?? throw new InvalidOperationException("Cache cannot be null");
        }

        public TimeSpan ConnectTimeout
        {
            get => transport.ConnectTimeout;
            set => transport.ConnectTimeout = value;
        }

        public bool CacheServiceTickets { get; set; }

        public AuthenticationOptions AuthenticationOptions { get; set; } = DefaultAuthentication;

        public KdcOptions KdcOptions { get => (KdcOptions)(AuthenticationOptions & ~AuthenticationOptions.AllAuthentication); }

        public string DefaultDomain { get; private set; }

        private Guid? scopeId;

        public Guid ScopeId
        {
            get => scopeId ?? (scopeId = KerberosConstants.GetRequestActivityId()).Value;
            set => scopeId = value;
        }

        public async Task Authenticate(KerberosCredential credential)
        {
            credential.Validate();

            int preauthAttempts = 0;

            AuthenticationOptions &= ~AuthenticationOptions.PreAuthenticate;

            using (logger.BeginRequestScope(ScopeId))
            {
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
                            logger.LogKerberosProtocolException(pex);
                            throw;
                        }

                        credential.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());

                        AuthenticationOptions |= AuthenticationOptions.PreAuthenticate;
                    }
                }
                while (true);
            }
        }

        public async Task<ApplicationSessionContext> GetServiceTicket(RequestServiceTicket rst, CancellationToken cancellation = default)
        {
            using (logger.BeginRequestScope(ScopeId))
            {
                cancellation.ThrowIfCancellationRequested();

                var tgtEntry = await CopyTgt($"krbtgt/{DefaultDomain}");

                if (rst.KdcOptions == 0)
                {
                    rst.KdcOptions = KdcOptions;
                }

                if (rst.UserToUserTicket != null)
                {
                    rst.KdcOptions |= KdcOptions.EncTktInSkey;
                }

                if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
                {
                    rst.KdcOptions |= KdcOptions.Forwardable;
                }

                var serviceTicketCacheEntry = await Cache.Get<KerberosClientCacheEntry>(rst.ServicePrincipalName, rst.S4uTarget);

                if (serviceTicketCacheEntry.Ticket == null || !CacheServiceTickets)
                {
                    serviceTicketCacheEntry = await RequestTgs(rst, tgtEntry, cancellation);
                }

                var encKdcRepPart = serviceTicketCacheEntry.Ticket.EncPart.Decrypt(
                    serviceTicketCacheEntry.SessionKey.AsKey(),
                    KeyUsage.EncTgsRepPartSubSessionKey,
                    d => KrbEncTgsRepPart.DecodeApplication(d)
                );

                return new ApplicationSessionContext
                {
                    ApReq = KrbApReq.CreateApReq(
                        serviceTicketCacheEntry.Ticket,
                        encKdcRepPart.Key.AsKey(),
                        rst.ApOptions,
                        out KrbAuthenticator authenticator
                    ),
                    SessionKey = authenticator.Subkey,
                    CTime = authenticator.CTime,
                    CuSec = authenticator.CuSec,
                    SequenceNumber = authenticator.SequenceNumber
                };
            }
        }

        public async Task<KrbApReq> GetServiceTicket(
            string spn,
            ApOptions options = DefaultApOptions,
            string s4u = null,
            KrbTicket s4uTicket = null,
            KrbTicket u2uServerTicket = null
        )
        {
            var session = await GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = spn,
                    ApOptions = options,
                    S4uTarget = s4u,
                    S4uTicket = s4uTicket,
                    UserToUserTicket = u2uServerTicket
                },
                cancellation.Token
            );

            return session.ApReq;
        }

        private async Task<KerberosClientCacheEntry> RequestTgs(
            RequestServiceTicket rst,
            KerberosClientCacheEntry tgtEntry,
            CancellationToken cancellation
        )
        {
            logger.LogInformation(
                "Requesting TGS for {SPN}; S4U = {S4U}; S4UTicket = {S4UTicketSPN}",
                rst.ServicePrincipalName,
                rst.S4uTarget,
                rst.S4uTicket?.SName
            );

            var tgsReq = KrbTgsReq.CreateTgsReq(rst, tgtEntry.SessionKey, tgtEntry.Ticket, out KrbEncryptionKey subkey);

            var encodedTgs = tgsReq.EncodeApplication();

            cancellation.ThrowIfCancellationRequested();

            var tgsRep = await transport.SendMessage<KrbTgsRep>(
                tgsReq.Body.Realm,
                encodedTgs,
                cancellation
            );

            var entry = new KerberosClientCacheEntry
            {
                Ticket = tgsRep,
                SessionKey = subkey
            };

            await Cache.Add(new TicketCacheEntry
            {
                Key = rst.ServicePrincipalName,
                Container = rst.S4uTarget,
                Expires = tgsReq.Body.Till,
                Value = entry
            });

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

                entry.SessionKey = KrbEncryptionKey.Decode(entry.SessionKey.Encode());
                entry.Ticket = KrbKdcRep.Decode(entry.Ticket.Encode());
            }

            return entry;
        }

        public async Task RenewTicket()
        {
            var entry = await CopyTgt($"krbtgt/{DefaultDomain}");

            var tgs = KrbTgsReq.CreateTgsReq(
                new RequestServiceTicket
                {
                    ServicePrincipalName = "krbtgt",
                    KdcOptions = KdcOptions
                },
                entry.SessionKey,
                entry.Ticket,
                out KrbEncryptionKey subkey
            );

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
            var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions);

            var asReq = asReqMessage.EncodeApplication();

            logger.LogTrace(
                "Attempting AS-REQ. UserName = {UserName}; Domain = {Domain}; Nonce = {Nonce}",
                credential.UserName,
                credential.Domain,
                asReqMessage.Body.Nonce
            );

            var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);

            var decrypted = credential.DecryptKdcRep(
                asRep,
                KeyUsage.EncAsRepPart,
                d => KrbEncAsRepPart.DecodeApplication(d)
            );

            if (decrypted.Nonce != asReqMessage.Body.Nonce)
            {
                throw new SecurityException(SR.Resource("KRB_ERROR_AS_NONCE_MISMATCH", asReqMessage.Body.Nonce, decrypted.Nonce));
            }

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

        private bool disposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    clientLoggingScope.Dispose();
                    cancellation.Dispose();
                }

                disposed = true;
            }
        }

        ~KerberosClient()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
