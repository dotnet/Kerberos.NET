using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Client
{
    public class KerberosClient : IDisposable
    {
        // - transport -> TCP/UDP/injected transport handler
        //
        // - KDC resolution -> specify DC name or use DNS resolution
        //                  -> DC resolver tries DC by locater instead
        //
        // - authenticate -> as-rep => TGT
        //                   -> request PAC
        //                   -> do not include pre-auth by default
        //                   -> automatically retry with pre-auth added
        //                   -> cache TGT/cache service ticket

        private const AuthenticationOptions DefaultAuthentication =
            AuthenticationOptions.RepPartCompatible |
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        private const ApOptions DefaultApOptions = 0;

        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private readonly object _syncTicketCache = new object();

        private readonly KerberosTransportSelector transport;
        private readonly ILogger<KerberosClient> logger;
        private readonly IDisposable clientLoggingScope;

        private ITicketCache ticketCache;
        private Guid? scopeId;
        private bool disposed = false;

        /// <summary>
        /// Create a new KerberosClient instance
        /// </summary>
        /// <param name="kdc">The pinned address of the KDC to communicate</param>
        /// <param name="logger">A logger instance for recording client logs</param>
        public KerberosClient(string kdc = null, ILoggerFactory logger = null)
            : this(logger, CreateTransports(kdc, logger))
        {
        }

        /// <summary>
        /// Create a KerberosClient instance
        /// </summary>
        /// <param name="logger">A logger instance for recording client logs</param>
        /// <param name="transports">A collection of network transports that the client
        /// will attempt to use to communicate with the KDC</param>
        public KerberosClient(ILoggerFactory logger = null, params IKerberosTransport[] transports)
        {
            this.logger = logger.CreateLoggerSafe<KerberosClient>();
            this.clientLoggingScope = this.logger.BeginScope("KerberosClient");

            transport = new KerberosTransportSelector(transports);

            Cache = new MemoryTicketCache(logger) { Refresh = this.Refresh };

            MaximumRetries = 10;
        }

        /// <summary>
        /// The number of KDC's the client will retry before failing the call.
        /// Default is 10 hosts, but limited by the total number of KDCs in the environment.
        /// </summary>
        public int MaximumRetries
        {
            get => transport.MaximumAttempts;
            set => transport.MaximumAttempts = value;
        }

        /// <summary>
        /// Determines whether the client attempt to renew tickets nearing expiration
        /// </summary>
        public bool RenewTickets
        {
            get => Cache.RefreshTickets;
            set => Cache.RefreshTickets = value;
        }

        /// <summary>
        /// Defines the threshold at which tickets are available to be renewed.
        /// A ticket must expire within this time period before it'll be considered.
        /// </summary>
        public TimeSpan RenewTicketsThreshold { get; set; } = TimeSpan.FromMinutes(15);

        /// <summary>
        /// Defines how often the cache is polled to check for expiring tickets.
        /// </summary>
        public TimeSpan RefreshPollInterval
        {
            get => Cache.RefreshInterval;
            set => Cache.RefreshInterval = value;
        }

        /// <summary>
        /// The transports this client will attempt to use to communicate with the KDC
        /// </summary>
        public IEnumerable<IKerberosTransport> Transports => transport.Transports;

        /// <summary>
        /// The cache that stores tickets for this client instance
        /// </summary>
        public ITicketCache Cache
        {
            get => ticketCache;
            set => ticketCache = value ?? throw new InvalidOperationException("Cache cannot be null");
        }

        /// <summary>
        /// The maximum time a transport can try connecting to the KDC before timing out
        /// </summary>
        public TimeSpan ConnectTimeout
        {
            get => transport.ConnectTimeout;
            set => transport.ConnectTimeout = value;
        }

        public TimeSpan SendTimeout
        {
            get => transport.SendTimeout;
            set => transport.SendTimeout = value;
        }

        public TimeSpan ReceiveTimeout
        {
            get => transport.ReceiveTimeout;
            set => transport.ReceiveTimeout = value;
        }

        /// <summary>
        /// Indicates whether the client should cache service tickets.
        /// Ticket-Granting-Tickets are always cached.
        /// </summary>
        public bool CacheServiceTickets { get; set; } = true;

        /// <summary>
        /// The Kerberos options used during the AS-REQ flow.
        /// </summary>
        public AuthenticationOptions AuthenticationOptions { get; set; } = DefaultAuthentication;

        /// <summary>
        /// The kerberos options used during the TGS-REQ flow.
        /// </summary>
        public KdcOptions KdcOptions { get => (KdcOptions)(AuthenticationOptions & ~AuthenticationOptions.AllAuthentication); }

        /// <summary>
        /// The realm of the currently authenticated user.
        /// </summary>
        public string DefaultDomain { get; protected set; }

        /// <summary>
        /// The logging Id of this client instance.
        /// </summary>
        public Guid ScopeId
        {
            get => scopeId ?? (scopeId = KerberosConstants.GetRequestActivityId()).Value;
            set => scopeId = value;
        }

        /// <summary>
        /// Initiates an AS-REQ to get a Ticket-Granting-Ticket for the provided credentials
        /// </summary>
        /// <param name="credential">The credential used to authenticate the user</param>
        /// <returns>Returns an awaitable task</returns>
        public async Task Authenticate(KerberosCredential credential)
        {
            credential.Validate();

            int preauthAttempts = 0;

            // The KDC may not require pre-auth so we shouldn't try it until the KDC indicates otherwise

            if (!credential.SupportsOptimisticPreAuthentication)
            {
                AuthenticationOptions &= ~AuthenticationOptions.PreAuthenticate;
            }

            using (logger.BeginRequestScope(ScopeId))
            {
                do
                {
                    try
                    {
                        // Authenticate to the KDC and if it succeeds break out of the retry loop

                        await RequestTgt(credential);
                        break;
                    }
                    catch (KerberosProtocolException pex)
                    {
                        // the attempt didn't succeed because the KDC returned a KRB-ERROR
                        // Some errors like KDC_ERR_PREAUTH_REQUIRED are not fatal so we
                        // can correct the request and retry in the next loop iteration

                        if (pex?.Error?.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                        {
                            // in this case we don't know what it was so bail

                            logger.LogKerberosProtocolException(pex);
                            throw;
                        }

                        // the usual case is KDC requires pre-auth and it's provided hints to what it's
                        // willing to accept for this. Usually it's ETypes and Salt information for pwd

                        credential.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());

                        foreach (var salt in credential.Salts)
                        {
                            logger.LogDebug("AS-REP PA-Data: EType = {Etype}; Salt = {Salt};", salt.Key, salt.Value);
                        }

                        // now we try pre-auth

                        AuthenticationOptions |= AuthenticationOptions.PreAuthenticate;
                    }
                }
                while (++preauthAttempts <= 3);
            }
        }

        /// <summary>
        /// Request a service ticket from a KDC using TGS-REQ
        /// </summary>
        /// <param name="rst">The parameters of the request</param>
        /// <param name="cancellation">A cancellation token to exit the request early</param>
        /// <returns>Returns a <see cref="ApplicationSessionContext"/> containing the service ticket</returns>
        public async Task<ApplicationSessionContext> GetServiceTicket(
            RequestServiceTicket rst,
            CancellationToken cancellation = default
        )
        {
            // attempt to normalize the SPN we're trying to get a ticket to
            // holding it here because the request may need intermediate tickets
            // if we have to cross realms

            var originalServicePrincipalName = KrbPrincipalName.FromString(rst.ServicePrincipalName);

            var tgtCacheName = $"krbtgt/{DefaultDomain}";
            var receivedRequestedTicket = false;

            using (logger.BeginRequestScope(ScopeId))
            {
                KrbEncTgsRepPart encKdcRepPart = null;
                KrbEncryptionKey sessionKey;
                KerberosClientCacheEntry serviceTicketCacheEntry;

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

                do
                {
                    cancellation.ThrowIfCancellationRequested();

                    // first of all, do we already have the ticket?

                    serviceTicketCacheEntry = Cache.GetCacheItem<KerberosClientCacheEntry>(
                        originalServicePrincipalName.FullyQualifiedName,
                        rst.S4uTarget
                    );

                    bool cacheResult = false;

                    if (serviceTicketCacheEntry.KdcResponse == null || !CacheServiceTickets)
                    {
                        // nope, try and request it from the KDC that issued the TGT

                        var tgtEntry = CopyTicket(tgtCacheName);

                        rst.Realm = ResolveKdcTarget(tgtEntry);

                        serviceTicketCacheEntry = await RequestTgs(rst, tgtEntry, cancellation);

                        cacheResult = true;
                    }

                    // we got a ticket of some sort from the cache or the KDC

                    KrbPrincipalName respondedSName;

                    if (serviceTicketCacheEntry.KdcResponse?.EncPart?.Cipher.Length > 0)
                    {
                        encKdcRepPart = serviceTicketCacheEntry.KdcResponse.EncPart.Decrypt(
                            serviceTicketCacheEntry.SessionKey.AsKey(),
                            serviceTicketCacheEntry.SessionKey.Usage,
                            d => KrbEncTgsRepPart.DecodeApplication(d)
                        );

                        VerifyNonces(serviceTicketCacheEntry.Nonce, encKdcRepPart.Nonce);

                        sessionKey = encKdcRepPart.Key;
                        respondedSName = encKdcRepPart.SName;
                    }
                    else
                    {
                        // cache shortcut when using krb5cc
                        sessionKey = serviceTicketCacheEntry.SessionKey;
                        respondedSName = serviceTicketCacheEntry.SName;
                    }

                    receivedRequestedTicket = false;

                    // is it a realm referral

                    if (originalServicePrincipalName.Name.Length == 1 &&
                        respondedSName.FullyQualifiedName.StartsWith(originalServicePrincipalName.FullyQualifiedName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        // It's not a realm referral but it is the singly-named thing we asked for (e.g. "krbtgt")

                        receivedRequestedTicket = true;
                    }
                    else if (!respondedSName.Matches(originalServicePrincipalName) &&
                             respondedSName.IsKrbtgt())
                    {
                        // it is a realm referral and we need to chase it

                        string referral = TryFindReferralShortcut(encKdcRepPart);

                        if (string.IsNullOrWhiteSpace(referral))
                        {
                            referral = originalServicePrincipalName.FullyQualifiedName;
                        }

                        rst.ServicePrincipalName = referral;

                        receivedRequestedTicket = false;

                        tgtCacheName = respondedSName.FullyQualifiedName;
                        serviceTicketCacheEntry.SessionKey = encKdcRepPart.Key;
                    }
                    else
                    {
                        // it's actually the ticket we requested

                        receivedRequestedTicket = true;
                    }

                    if (cacheResult)
                    {
                        // regardless of what state we're in we got a valuable ticket
                        // that can be used in future requests

                        Cache.Add(new TicketCacheEntry
                        {
                            Key = respondedSName.FullyQualifiedName,
                            Container = rst.S4uTarget,
                            RenewUntil = encKdcRepPart.RenewTill,
                            Expires = encKdcRepPart.EndTime,
                            Value = serviceTicketCacheEntry
                        });
                    }

                    // if we didn't receive the ticket we requested but got a referral
                    // we need to kick off a new request
                }
                while (!receivedRequestedTicket);

                // finally we got what we asked for

                return new ApplicationSessionContext
                {
                    ApReq = KrbApReq.CreateApReq(
                        serviceTicketCacheEntry.KdcResponse,
                        sessionKey.AsKey(),
                        rst.ApOptions,
                        out KrbAuthenticator authenticator
                    ),
                    SessionKey = authenticator.Subkey ?? sessionKey,
                    CTime = authenticator.CTime,
                    CuSec = authenticator.CuSec,
                    SequenceNumber = authenticator.SequenceNumber
                };
            }
        }

        private string TryFindReferralShortcut(KrbEncTgsRepPart encKdcRepPart)
        {
            var svrReferralPaData = encKdcRepPart.EncryptedPaData?.MethodData?.FirstOrDefault(d => d.Type == PaDataType.PA_SVR_REFERRAL_INFO);

            if (svrReferralPaData == null)
            {
                return null;
            }

            var svrReferral = KrbPaSvrReferralData.Decode(svrReferralPaData.Value);

            return $"krbtgt/{svrReferral.ReferredRealm}";
        }

        private static string ResolveKdcTarget(KerberosClientCacheEntry tgtEntry)
        {
            var ticket = tgtEntry.KdcResponse.Ticket;

            if (ticket.SName.Name.Length > 1 && ticket.SName.IsKrbtgt())
            {
                return ticket.SName.Name[1];
            }

            return ticket.Realm;
        }

        /// <summary>
        /// Request a service ticket from a KDC using TGS-REQ
        /// </summary>
        /// <param name="spn">The SPN of the requested service</param>
        /// <param name="options">Authentication options for the request</param>
        /// <param name="s4u">The optional account name of the user this service is trying to get a ticket on-behalf-of</param>
        /// <param name="s4uTicket">The optional service ticket that grants the S4U privilege</param>
        /// <param name="u2uServerTicket">The optional user-to-user (encrypt in session key) TGT</param>
        /// <returns>Returns the requested <see cref="KrbApReq"/></returns>
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

        private async Task Refresh(MemoryTicketCache.CacheEntry entry)
        {
            // optimistically try and refresh a cached ticket if it's renewable
            // however tickets that are already expired can't be renewed

            if (entry.IsExpired())
            {
                return;
            }

            var renewUntil = entry.RenewUntil ?? DateTimeOffset.MinValue;

            // if RenewUntil isn't set or we're past that window we can't renew
            // or if it's renewable but the ticket expiration is already greater
            // than the entire renewal window (you'll just get the same ticket back)

            DateTimeOffset ttlRenew;

            if (renewUntil > DateTimeOffset.MinValue)
            {
                ttlRenew = renewUntil - entry.TimeToLive;
            }

            if (renewUntil < DateTimeOffset.UtcNow || ttlRenew <= DateTimeOffset.UtcNow)
            {
                return;
            }

            // we also don't want to renew too early otherwise it's a waste of energy
            // only renew if the ticket is nearing expiration

            if (IsRenewable(entry, out KerberosClientCacheEntry ticket))
            {
                var cname = ticket.KdcResponse.CName.FullyQualifiedName;
                var sname = ticket.KdcResponse.Ticket.SName.FullyQualifiedName;

                logger.LogInformation("Ticket for {CName} to {SName} is renewing because it's expiring in {TTL}", cname, sname, entry.TimeToLive);

                await RenewTicket(sname);
            }
        }

        private bool IsRenewable(MemoryTicketCache.CacheEntry entry, out KerberosClientCacheEntry ticket)
        {
            ticket = default;

            if (entry.Value is KerberosClientCacheEntry tick)
            {
                if (entry.TimeToLive <= TimeSpan.Zero || entry.TimeToLive > RenewTicketsThreshold)
                {
                    return false;
                }

                // keep it simple. Only ever renew TGTs.

                if (tick.KdcResponse.Ticket.SName.IsKrbtgt())
                {
                    ticket = tick;
                    return true;
                }
            }

            return false;
        }

        private async Task<KerberosClientCacheEntry> RequestTgs(
            RequestServiceTicket rst,
            KerberosClientCacheEntry tgtEntry,
            CancellationToken cancellation
        )
        {
            logger.LogInformation(
                "Requesting TGS for {SPN}; TGT Realm = {TGTRealm}; TGT Service = {TGTService}; S4U = {S4U}; S4UTicket = {S4UTicketSPN}",
                rst.ServicePrincipalName,
                tgtEntry.KdcResponse.CRealm,
                tgtEntry.KdcResponse.Ticket.SName.FullyQualifiedName,
                rst.S4uTarget,
                rst.S4uTicket?.SName
            );

            var tgsReq = KrbTgsReq.CreateTgsReq(rst, tgtEntry.SessionKey, tgtEntry.KdcResponse, out KrbEncryptionKey sessionKey);

            var encodedTgs = tgsReq.EncodeApplication();

            cancellation.ThrowIfCancellationRequested();

            var tgsRep = await transport.SendMessage<KrbTgsRep>(
                rst.Realm,
                encodedTgs,
                cancellation
            );

            var entry = new KerberosClientCacheEntry
            {
                KdcResponse = tgsRep,
                SessionKey = sessionKey,
                Nonce = tgsReq.Body.Nonce
            };

            logger.LogInformation("TGS-REP for {SPN}", tgsRep.Ticket.SName.FullyQualifiedName);

            return entry;
        }

        private KerberosClientCacheEntry CopyTicket(string spn)
        {
            var entry = Cache.GetCacheItem<KerberosClientCacheEntry>(spn);

            lock (_syncTicketCache)
            {
                if (entry.KdcResponse == null)
                {
                    throw new InvalidOperationException("Cannot request a service ticket until a user is authenticated");
                }

                var usage = entry.SessionKey.Usage;

                entry.SessionKey = KrbEncryptionKey.Decode(entry.SessionKey.Encode());
                entry.SessionKey.Usage = usage;

                entry.KdcResponse = KrbKdcRep.Decode(entry.KdcResponse.Encode());
            }

            return entry;
        }

        /// <summary>
        /// Attempt to renew a valid ticket still in the cache
        /// </summary>
        /// <param name="spn">The SPN of the ticket to renew. Defaults to the krbtgt ticket.</param>
        /// <returns>Returns an awaitable task</returns>
        public async Task RenewTicket(string spn = null)
        {
            if (string.IsNullOrWhiteSpace(spn))
            {
                spn = $"krbtgt/{DefaultDomain}";
            }

            var entry = CopyTicket(spn);

            var tgs = KrbTgsReq.CreateTgsReq(
                new RequestServiceTicket
                {
                    ServicePrincipalName = spn,
                    KdcOptions = KdcOptions | KdcOptions.Renew | KdcOptions.RenewableOk,
                    Realm = ResolveKdcTarget(entry)
                },
                entry.SessionKey,
                entry.KdcResponse,
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

            CacheTgt(tgsRep, encKdcRepPart);
        }

        private void CacheTgt(KrbKdcRep kdcRep, KrbEncKdcRepPart encKdcRepPart)
        {
            var key = kdcRep.Ticket.SName.FullyQualifiedName;

            encKdcRepPart.Key.Usage = KeyUsage.EncTgsRepPartSessionKey;

            Cache.Add(new TicketCacheEntry
            {
                Key = key,
                Expires = encKdcRepPart.EndTime,
                RenewUntil = encKdcRepPart.RenewTill,
                Value = new KerberosClientCacheEntry
                {
                    SessionKey = encKdcRepPart.Key,
                    KdcResponse = kdcRep
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
                d => DecodeEncKdcRepPart<KrbEncAsRepPart>(d)
            );

            VerifyNonces(asReqMessage.Body.Nonce, decrypted.Nonce);

            DefaultDomain = credential.Domain;

            CacheTgt(asRep, decrypted);
        }

        private KrbEncKdcRepPart DecodeEncKdcRepPart<T>(ReadOnlyMemory<byte> decrypted)
            where T : KrbEncKdcRepPart, new()
        {
            // Certain legacy Kerberos implementations will return EncTgsRepPart instead
            // of EncAsRepPart for historical reasons and when that happens this breaks.
            // We should honor that and detect what type it is.
            //
            // https://tools.ietf.org/html/rfc4120#section-5.4.2
            //
            // Compatibility note: Some implementations unconditionally send an
            // encrypted EncTGSRepPart (application tag number 26) in this field
            // regardless of whether the reply is a AS-REP or a TGS-REP.  In the
            // interest of compatibility, implementors MAY relax the check on the
            // tag number of the decrypted ENC-PART.

            KrbEncKdcRepPart repPart = null;

            if (KrbEncAsRepPart.CanDecode(decrypted))
            {
                repPart = KrbEncAsRepPart.DecodeApplication(decrypted);
            }
            else if (KrbEncTgsRepPart.CanDecode(decrypted))
            {
                repPart = KrbEncTgsRepPart.DecodeApplication(decrypted);
            }

            if (repPart != null)
            {
                logger.LogDebug(
                    "EncPart expected to be {ExpectedType} and is actually {ActualType}",
                    typeof(T).Name,
                    repPart.GetType().Name
                );

                if (AuthenticationOptions.HasFlag(AuthenticationOptions.RepPartCompatible) || repPart is T)
                {
                    return repPart;
                }
            }

            throw new KerberosProtocolException(KerberosErrorCode.KDC_ERR_BADOPTION);
        }

        private static void VerifyNonces(int reqNonce, int repNonce)
        {
            if (repNonce != reqNonce)
            {
                throw new SecurityException(SR.Resource("KRB_ERROR_AS_NONCE_MISMATCH", reqNonce, repNonce));
            }
        }

        private static IKerberosTransport[] CreateTransports(string kdc, ILoggerFactory logger)
        {
            return new IKerberosTransport[]
            {
                new UdpKerberosTransport(kdc),
                new TcpKerberosTransport(logger, kdc)
            };
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    if (Cache is IDisposable cache)
                    {
                        cache.Dispose();
                    }

                    transport.Dispose();

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
