// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography.Asn1;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using static Kerberos.NET.Entities.KerberosConstants;

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

        private const GssContextEstablishmentFlag DefaultGssContextFlags =
                       GssContextEstablishmentFlag.GSS_C_REPLAY_FLAG |
                       GssContextEstablishmentFlag.GSS_C_SEQUENCE_FLAG |
                       GssContextEstablishmentFlag.GSS_C_CONF_FLAG |
                       GssContextEstablishmentFlag.GSS_C_INTEG_FLAG |
                       GssContextEstablishmentFlag.GSS_C_EXTENDED_ERROR_FLAG;

        private const ApOptions DefaultApOptions = 0;

        private readonly CancellationTokenSource cancellation = new CancellationTokenSource();
        private readonly object _syncTicketCache = new object();

        private readonly KerberosTransportSelector transport;
        private readonly ILoggerFactory loggerFactory;
        private readonly ILogger<KerberosClient> logger;
        private readonly IDisposable clientLoggingScope;

        private ITicketCache ticketCache;
        private Guid? scopeId;
        private bool cacheSet;
        private bool disposed = false;

        /// <summary>
        /// Create a new KerberosClient instance.
        /// </summary>
        /// <param name="config">The custom configuration this client should use when making Kerberos requests.</param>
        /// <param name="logger">A logger instance for recording client logs</param>
        public KerberosClient(Krb5Config config = null, ILoggerFactory logger = null)
            : this(config, logger, CreateTransports(logger))
        {
        }

        /// <summary>
        /// Create a KerberosClient instance.
        /// </summary>
        /// <param name="config">The custom configuration this client should use when making Kerberos requests.</param>
        /// <param name="logger">A logger instance for recording client logs</param>
        /// <param name="transports">A collection of network transports that the client
        /// will attempt to use to communicate with the KDC</param>
        public KerberosClient(Krb5Config config = null, ILoggerFactory logger = null, params IKerberosTransport[] transports)
        {
            this.Configuration = config ?? Krb5ConfigurationSerializer.Deserialize(string.Empty).ToConfigObject();

            this.loggerFactory = logger;
            this.logger = logger.CreateLoggerSafe<KerberosClient>();
            this.clientLoggingScope = this.logger.BeginScope("KerberosClient");

            this.transport = new KerberosTransportSelector(transports, this.Configuration, logger)
            {
                ScopeId = this.ScopeId
            };

            this.MaximumRetries = 10;
        }

        /// <summary>
        /// The custom configuration this client should use when making Kerberos requests.
        /// </summary>
        [KerberosIgnore]
        public Krb5Config Configuration { get; }

        /// <summary>
        /// The number of KDC's the client will retry before failing the call.
        /// Default is 10 hosts, but limited by the total number of KDCs in the environment.
        /// </summary>
        public int MaximumRetries
        {
            get => this.transport.MaximumAttempts;
            set => this.transport.MaximumAttempts = value;
        }

        /// <summary>
        /// Determines whether the client attempt to renew tickets nearing expiration
        /// </summary>
        public bool RenewTickets
        {
            get => this.Cache.RefreshTickets;
            set => this.Cache.RefreshTickets = value;
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
            get => this.Cache.RefreshInterval;
            set => this.Cache.RefreshInterval = value;
        }

        /// <summary>
        /// The transports this client will attempt to use to communicate with the KDC
        /// </summary>
        public IEnumerable<IKerberosTransport> Transports => this.transport.Transports;

        /// <summary>
        /// The cache that stores tickets for this client instance
        /// </summary>
        [KerberosIgnore]
        public ITicketCache Cache
        {
            get
            {
                this.SetupCache();

                return this.ticketCache;
            }
            set
            {
                if (this.ticketCache is IDisposable disposable)
                {
                    try
                    {
                        disposable.Dispose();
                    }
                    catch (Exception ex)
                    {
                        this.logger.LogError(ex, "Ticket cache disposal failed");
                    }

                    this.ticketCache = null;
                    this.cacheSet = false;
                }

                this.ticketCache = value ?? throw new InvalidOperationException("Cache cannot be null");
                this.cacheSet = true;
            }
        }

        /// <summary>
        /// The maximum time a transport can try connecting to the KDC before timing out
        /// </summary>
        public TimeSpan ConnectTimeout
        {
            get => this.transport.ConnectTimeout;
            set => this.transport.ConnectTimeout = value;
        }

        public TimeSpan SendTimeout
        {
            get => this.transport.SendTimeout;
            set => this.transport.SendTimeout = value;
        }

        public TimeSpan ReceiveTimeout
        {
            get => this.transport.ReceiveTimeout;
            set => this.transport.ReceiveTimeout = value;
        }

        public int MaximumReferralLoops { get; set; } = 10;

        /// <summary>
        /// Indicates whether the client should cache service tickets.
        /// Ticket-Granting-Tickets are always cached.
        /// </summary>
        public bool CacheServiceTickets { get; set; } = true;

        /// <summary>
        /// Indicates that the cache should override configuration and always store in memory only.
        /// Defaults to true for backwards compatibility.
        /// </summary>
        public bool CacheInMemory { get; set; } = true;

        /// <summary>
        /// The Kerberos options used during the AS-REQ flow.
        /// </summary>
        public AuthenticationOptions AuthenticationOptions { get; set; } = DefaultAuthentication;

        /// <summary>
        /// The kerberos options used during the TGS-REQ flow.
        /// </summary>
        public KdcOptions KdcOptions => (KdcOptions)(this.AuthenticationOptions & ~AuthenticationOptions.AllAuthentication);

        /// <summary>
        /// The realm of the currently authenticated user.
        /// </summary>
        public string DefaultDomain
        {
            get => this.Cache?.DefaultDomain ?? this.Configuration.Defaults.DefaultRealm;
            protected set => this.Configuration.Defaults.DefaultRealm = value;
        }

        /// <summary>
        /// The logging Id of this client instance.
        /// </summary>
        public Guid ScopeId
        {
            get => this.scopeId ?? (this.scopeId = GetRequestActivityId()).Value;
            set => this.scopeId = value;
        }

        public string UserPrincipalName
        {
            get
            {
                try
                {
                    var tgt = this.CopyTicket($"krbtgt/{this.DefaultDomain}");

                    return tgt.KdcResponse.CName.FullyQualifiedName;
                }
                catch (InvalidOperationException)
                {
                    return null;
                }
            }
        }

        /// <summary>
        /// Reset any connection state that may be cached from previous attempts.
        /// </summary>
        public void ResetConnections()
        {
            foreach (var t in this.Transports.OfType<KerberosTransportBase>())
            {
                t.ClientRealmService.ResetConnections();
            }
        }

        /// <summary>
        /// Prioritize the use of a specific KDC address for the provided realm. Note that calls to this
        /// method are additive and do not overwrite previously pinned addresses. If you need to remove an address
        /// you should call <see cref="ClearPinnedKdc(string)" />.
        /// </summary>
        /// <param name="realm">The realm that will have a prioritized KDC.</param>
        /// <param name="kdc">The KDC to prioritize.</param>
        public void PinKdc(string realm, string kdc)
        {
            if (string.IsNullOrWhiteSpace(realm))
            {
                throw new ArgumentNullException(nameof(realm));
            }

            if (string.IsNullOrWhiteSpace(kdc))
            {
                throw new ArgumentNullException(nameof(kdc));
            }

            foreach (var t in this.Transports.OfType<KerberosTransportBase>())
            {
                t.ClientRealmService.PinKdc(realm, kdc);
            }
        }

        /// <summary>
        /// Removes any previously pinned KDC addresses for the provided realm.
        /// </summary>
        /// <param name="realm">The realm to remove the pinned addresses.</param>
        public void ClearPinnedKdc(string realm)
        {
            if (string.IsNullOrWhiteSpace(realm))
            {
                throw new ArgumentNullException(nameof(realm));
            }

            foreach (var t in this.Transports.OfType<KerberosTransportBase>())
            {
                t.ClientRealmService.ClearPinnedKdc(realm);
            }
        }

        /// <summary>
        /// Initiates an AS-REQ to get a Ticket-Granting-Ticket for the provided credentials
        /// </summary>
        /// <param name="credential">The credential used to authenticate the user</param>
        /// <returns>Returns an awaitable task</returns>
        public async Task Authenticate(KerberosCredential credential)
        {
            if (credential == null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            credential.Validate();

            credential.Configuration = this.Configuration;

            // The KDC may not require pre-auth so we shouldn't try it until the KDC indicates otherwise

            if (!credential.SupportsOptimisticPreAuthentication)
            {
                this.AuthenticationOptions &= ~AuthenticationOptions.PreAuthenticate;
            }

            if (!this.Configuration.Defaults.Canonicalize)
            {
                this.AuthenticationOptions &= ~AuthenticationOptions.Canonicalize;
            }

            if (this.Configuration.Defaults.Proxiable)
            {
                this.AuthenticationOptions |= AuthenticationOptions.Proxiable;
            }

            if (this.Configuration.Defaults.Forwardable)
            {
                this.AuthenticationOptions |= AuthenticationOptions.Forwardable;
            }

            if (!this.Configuration.Defaults.RequestPac)
            {
                this.AuthenticationOptions &= ~AuthenticationOptions.IncludePacRequest;
            }

            using (this.logger.BeginRequestScope(this.ScopeId))
            {
                await this.AuthenticateCredential(credential);
            }
        }

        private async Task AuthenticateCredential(KerberosCredential credential)
        {
            int preauthAttempts = 0;

            bool succeeded = false;
            bool tryPinned = false;

            do
            {
                try
                {
                    // Authenticate to the KDC and if it succeeds break out of the retry loop

                    await this.RequestTgt(credential).ConfigureAwait(false);
                    succeeded = true;
                    break;
                }
                catch (KerberosProtocolException pex)
                {
                    // the attempt didn't succeed because the KDC returned a KRB-ERROR
                    // Some errors like KDC_ERR_PREAUTH_REQUIRED are not fatal so we
                    // can correct the request and retry in the next loop iteration

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_FAILED)
                    {
                        // if pre-auth fails it might be because the KDC doesn't have the latest
                        // copy of the password so we should try once more against a primary KDC

                        if (this.TryPinPrimaryKdc(credential.Domain))
                        {
                            tryPinned = true;
                            continue;
                        }
                    }

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_POLICY)
                    {
                        HandlePolicyViolation(pex);
                    }

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        this.ConfigurePreAuth(credential, pex);
                        continue;
                    }

                    if (pex?.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_C_PRINCIPAL_UNKNOWN &&
                        credential.PrincipalNameType == PrincipalNameType.NT_ENTERPRISE)
                    {
                        credential.PrincipalNameType = PrincipalNameType.NT_PRINCIPAL;
                        continue;
                    }

                    // in this case we don't know what it was so bail

                    this.logger.LogKerberosProtocolException(pex);
                    throw;
                }
                finally
                {
                    if (succeeded && tryPinned)
                    {
                        this.ClearPinnedKdc(credential.Domain);
                    }
                }
            }
            while (++preauthAttempts <= 4);
        }

        private static void HandlePolicyViolation(KerberosProtocolException pex)
        {
            if (KrbErrorData.CanDecode(pex.Error.EData.Value))
            {
                var errorData = KrbErrorData.Decode(pex.Error.EData.Value);

                var decoded = errorData.DecodeExtendedError();

                throw decoded?.Status switch
                {
                    Win32.Win32StatusCode.STATUS_SMARTCARD_LOGON_REQUIRED => new KerberosPolicyException(PaDataType.PA_PK_AS_REQ),
                    _ => new KerberosPolicyException(decoded.Status),
                };
            }

            throw new KerberosPolicyException(pex.Message, pex);
        }

        private bool TryPinPrimaryKdc(string realm)
        {
            bool pinned = false;

            if (this.Configuration.Realms.TryGetValue(realm, out Krb5RealmConfig config) && config.PrimaryKdc != null)
            {
                foreach (var primaryKdc in config.PrimaryKdc)
                {
                    if (!pinned)
                    {
                        this.ClearPinnedKdc(realm);
                    }

                    this.PinKdc(realm, primaryKdc);

                    pinned = true;
                }
            }

            return pinned;
        }

        private void ConfigurePreAuth(KerberosCredential credential, KerberosProtocolException pex)
        {
            // the usual case is KDC requires pre-auth and it's provided hints to what it's
            // willing to accept for this. Usually it's ETypes and Salt information for pwd

            credential.IncludePreAuthenticationHints(pex?.Error?.DecodePreAuthentication());

            foreach (var salt in credential.Salts)
            {
                this.logger.LogDebug("AS-REP PA-Data: EType = {Etype}; Salt = {Salt};", salt.Key, salt.Value);
            }

            // now we try pre-auth

            this.AuthenticationOptions |= AuthenticationOptions.PreAuthenticate;
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
            if (rst.GssContextFlags == 0)
            {
                rst.GssContextFlags = DefaultGssContextFlags;
            }

            if (rst.GssContextFlags == GssContextEstablishmentFlag.GSS_C_NONE)
            {
                rst.GssContextFlags = 0;
            }

            if (rst.ApOptions.HasFlag(ApOptions.MutualRequired))
            {
                rst.GssContextFlags |= GssContextEstablishmentFlag.GSS_C_MUTUAL_FLAG;
            }

            // attempt to normalize the SPN we're trying to get a ticket to
            // holding it here because the request may need intermediate tickets
            // if we have to cross realms

            var requestedServicePrincipalName = KrbPrincipalName.FromString(rst.ServicePrincipalName);

            if (this.Configuration.Defaults.DnsCanonicalizeHostname)
            {
                requestedServicePrincipalName.Canonicalize(this.Configuration.Defaults.QualifyShortname);

                rst.ServicePrincipalName = requestedServicePrincipalName.FullyQualifiedName;
            }

            if (string.IsNullOrWhiteSpace(this.DefaultDomain) &&
                !string.IsNullOrWhiteSpace(this.ticketCache.DefaultDomain))
            {
                this.DefaultDomain = this.ticketCache.DefaultDomain;
            }

            var tgtCacheName = $"krbtgt/{this.DefaultDomain}";
            var receivedRequestedTicket = false;

            using (this.logger.BeginRequestScope(this.ScopeId))
            {
                KrbEncTgsRepPart encKdcRepPart = null;
                KerberosClientCacheEntry serviceTicketCacheEntry = default;

                if (this.KdcOptions == 0)
                {
                    this.AuthenticationOptions |= (AuthenticationOptions)this.Configuration.Defaults.KdcDefaultOptions;
                }

                if (rst.KdcOptions == 0)
                {
                    rst.KdcOptions = this.KdcOptions;
                }

                if (rst.UserToUserTicket != null)
                {
                    rst.KdcOptions |= KdcOptions.EncTktInSkey;
                }

                if (!string.IsNullOrWhiteSpace(rst.S4uTarget))
                {
                    rst.KdcOptions |= KdcOptions.Forwardable;
                }

                if (rst.Configuration == null)
                {
                    rst.Configuration = this.Configuration;
                }

                int referralCount = 0;

                do
                {
                    cancellation.ThrowIfCancellationRequested();

                    // first of all, do we already have the ticket?

                    if (rst.CanCacheTicket)
                    {
                        serviceTicketCacheEntry = this.Cache.GetCacheItem<KerberosClientCacheEntry>(
                            requestedServicePrincipalName.FullyQualifiedName,
                            rst.S4uTarget
                        );
                    }

                    bool cacheResult = false;

                    if (!serviceTicketCacheEntry.IsValid(ignoreExpiration: rst.CanRetrieveExpiredTickets) ||
                        !this.CacheServiceTickets ||
                        !rst.CanCacheTicket)
                    {
                        // nope, try and request it from the KDC that issued the TGT

                        logger.LogInformation("Cache did not contain a valid ticket for {Spn}", requestedServicePrincipalName.FullyQualifiedName);

                        var tgtEntry = this.CopyTicket(tgtCacheName);

                        logger.LogInformation(
                            "Using TGT from {CRealm} to {Realm}",
                            tgtEntry.KdcResponse.CRealm,
                            tgtEntry.KdcResponse.Ticket.SName.FullyQualifiedName
                        );

                        rst.Realm = ResolveKdcTarget(tgtEntry);
                        rst.KdcOptions = ReconcileKdcFlags(rst.KdcOptions, tgtEntry.Flags);

                        try
                        {
                            (serviceTicketCacheEntry, encKdcRepPart) = await this.RequestDecryptedTgs(
                                rst,
                                tgtEntry,
                                cancellation
                            ).ConfigureAwait(false);
                        }
                        catch (KerberosProtocolException pex)
                            when (pex.Error?.ErrorCode == KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN)
                        {
                            // the SPN was authoritatively not found, but that could be because it belongs to another domain
                            // usually the KDC will automatically refer us to the domain where it thinks it might be instead
                            // however, sometimes the KDC just doesn't know where we need to go so we check for a hint instead

                            logger.LogInformation("Service principal not found. Checking for realm hint. {SPN}", rst.ServicePrincipalName);

                            if (this.TryFindRealmHint(rst, out string referral) &&
                                !string.Equals(tgtCacheName, referral, StringComparison.InvariantCultureIgnoreCase))
                            {
                                logger.LogDebug("Realm hint found for {SPN} to {Realm}", rst.ServicePrincipalName, referral);

                                rst.ServicePrincipalName = referral;

                                continue;
                            }

                            logger.LogDebug("Realm hint not found");

                            throw;
                        }

                        cacheResult = rst.CacheTicket ?? true;
                    }

                    receivedRequestedTicket = false;

                    // is it a realm referral

                    if (requestedServicePrincipalName.Name.Length == 1 &&
                        serviceTicketCacheEntry.SName.FullyQualifiedName.StartsWith(requestedServicePrincipalName.FullyQualifiedName, StringComparison.InvariantCultureIgnoreCase))
                    {
                        // It's not a realm referral but it is the singly-named thing we asked for (e.g. "krbtgt")
                        logger.LogInformation(
                            "A service principal was found {Spn}: {SName}",
                            requestedServicePrincipalName.FullyQualifiedName,
                            serviceTicketCacheEntry.SName.FullyQualifiedName
                        );

                        receivedRequestedTicket = true;
                    }
                    else if (!serviceTicketCacheEntry.SName.Matches(requestedServicePrincipalName) &&
                             serviceTicketCacheEntry.SName.IsKrbtgt())
                    {
                        // it is a realm referral and we need to chase it

                        string referral = TryFindReferralShortcut(encKdcRepPart);

                        if (string.IsNullOrWhiteSpace(referral) ||
                            encKdcRepPart.SName.Matches(KrbPrincipalName.FromString(referral, PrincipalNameType.NT_SRV_INST)))
                        {
                            referral = requestedServicePrincipalName.FullyQualifiedName;
                        }

                        rst.ServicePrincipalName = referral;

                        receivedRequestedTicket = false;

                        tgtCacheName = serviceTicketCacheEntry.SName.FullyQualifiedName;

                        var usage = serviceTicketCacheEntry.SessionKey.Usage;

                        serviceTicketCacheEntry.SessionKey = encKdcRepPart.Key;

                        if (serviceTicketCacheEntry.SessionKey.Usage == KeyUsage.Unknown)
                        {
                            serviceTicketCacheEntry.SessionKey.Usage = usage;
                        }

                        logger.LogInformation(
                            "Referral is required for {Spn} => {Referral}",
                            requestedServicePrincipalName.FullyQualifiedName,
                            tgtCacheName
                        );
                    }
                    else
                    {
                        // it's actually the ticket we requested

                        logger.LogInformation(
                            "A ticket was retrieved for {Spn}",
                            serviceTicketCacheEntry.SName.FullyQualifiedName
                        );

                        receivedRequestedTicket = true;
                    }

                    if (cacheResult && (rst.CanCacheTicket || serviceTicketCacheEntry.SName.IsKrbtgt()))
                    {
                        // regardless of what state we're in we got a valuable ticket
                        // that can be used in future requests

                        this.Cache.Add(new TicketCacheEntry
                        {
                            Key = serviceTicketCacheEntry.SName.FullyQualifiedName,
                            Container = rst.S4uTarget,
                            RenewUntil = encKdcRepPart.RenewTill,
                            Expires = encKdcRepPart.EndTime,
                            Value = serviceTicketCacheEntry
                        });
                    }

                    // if we didn't receive the ticket we requested but got a referral
                    // we need to kick off a new request
                }
                while (!receivedRequestedTicket && ++referralCount < this.MaximumReferralLoops);

                if (referralCount >= this.MaximumReferralLoops)
                {
                    var ex = new KerberosProtocolException(KerberosErrorCode.KRB_AP_PATH_NOT_ACCEPTED, SR.Resource("ChasedReferralTooFar"));

                    logger.LogWarning(
                        ex,
                        "Have to bail out because too many referrals were issued (referral loop?): {Count}",
                        referralCount
                    );

                    throw ex;
                }

                // finally we got what we asked for

                return new ApplicationSessionContext
                {
                    ApReq = KrbApReq.CreateApReq(
                        serviceTicketCacheEntry.KdcResponse,
                        serviceTicketCacheEntry.SessionKey.AsKey(),
                        rst,
                        out KrbAuthenticator authenticator
                    ),
                    SessionKey = authenticator.Subkey ?? serviceTicketCacheEntry.SessionKey,
                    CTime = authenticator.CTime,
                    CuSec = authenticator.CuSec,
                    SequenceNumber = authenticator.SequenceNumber
                };
            }
        }

        private bool TryFindRealmHint(RequestServiceTicket rst, out string referral)
        {
            foreach (var kv in this.Configuration.DomainRealm)
            {
                //
                // .foo.net matches anything under foo.net
                //      bar.foo.net matches
                //      baz.foo.net matches
                //      baz.bar.foo.net matches
                //      foo.net does not match
                //      bar.net does not match
                //
                // bar.foo.net matches explicitly
                //      bar.foo.net matches
                //      baz.foo.net does not match
                //      baz.bar.foo.net does not match
                //      foo.net does not match
                //

                if ((kv.Key[0] == '.' && rst.ServicePrincipalName.EndsWith(kv.Key, StringComparison.OrdinalIgnoreCase)) ||
                    (string.Equals(kv.Key, rst.ServicePrincipalName, StringComparison.InvariantCultureIgnoreCase)))
                {
                    referral = $"krbtgt/{kv.Value.ToUpperInvariant()}";
                    return true;
                }
            }

            referral = null;
            return false;
        }

        private async Task<(KerberosClientCacheEntry serviceTicketCacheEntry, KrbEncTgsRepPart encKdcRepPart)> RequestDecryptedTgs(
            RequestServiceTicket rst,
            KerberosClientCacheEntry tgtEntry,
            CancellationToken cancellation
        )
        {
            var serviceTicketCacheEntry = await this.RequestTgs(rst, tgtEntry, cancellation).ConfigureAwait(false);

            var encKdcRepPart = serviceTicketCacheEntry.KdcResponse.EncPart.Decrypt(
               serviceTicketCacheEntry.SessionKey.AsKey(),
               serviceTicketCacheEntry.SessionKey.Usage,
               d => KrbEncTgsRepPart.DecodeApplication(d)
           );

            VerifyNonces(serviceTicketCacheEntry.Nonce, encKdcRepPart.Nonce);

            serviceTicketCacheEntry.Flags = encKdcRepPart.Flags;
            serviceTicketCacheEntry.AuthTime = encKdcRepPart.AuthTime;
            serviceTicketCacheEntry.StartTime = encKdcRepPart.StartTime ?? DateTimeOffset.MinValue;
            serviceTicketCacheEntry.EndTime = encKdcRepPart.EndTime;
            serviceTicketCacheEntry.RenewTill = encKdcRepPart.RenewTill;
            serviceTicketCacheEntry.SessionKey = encKdcRepPart.Key;
            serviceTicketCacheEntry.SName = encKdcRepPart.SName;

            return (serviceTicketCacheEntry, encKdcRepPart);
        }

        private static KdcOptions ReconcileKdcFlags(KdcOptions options, TicketFlags ticketFlags)
        {
            SetKdcOptionsFlag(ticketFlags, TicketFlags.Forwardable, KdcOptions.Forwardable, ref options);
            SetKdcOptionsFlag(ticketFlags, TicketFlags.Forwarded, KdcOptions.Forwarded, ref options);
            SetKdcOptionsFlag(ticketFlags, TicketFlags.Renewable, KdcOptions.Renewable, ref options);

            return options;
        }

        private static void SetKdcOptionsFlag(
            TicketFlags ticketFlags,
            TicketFlags ticketFlag,
            KdcOptions kdcFlag,
            ref KdcOptions options
        )
        {
            if ((ticketFlags & ticketFlag) == 0)
            {
                options &= ~kdcFlag;
            }
        }

        private void SetupCache()
        {
            if (this.cacheSet)
            {
                return;
            }

            var cachePath = Environment.ExpandEnvironmentVariables(this.Configuration.Defaults.DefaultCCacheName);

            if (!this.CacheInMemory && this.CacheServiceTickets && !string.IsNullOrWhiteSpace(cachePath))
            {
                TicketCacheBase.TryParseCacheType(cachePath, out string cacheType, out string path);

                switch (cacheType)
                {
                    case null:
                    case "MEMORY":
                    case "API":
                    case "DIR":
                    case "KEYRING":
                        break;
                    case "MSLSA":
                        this.SetLsaCache();
                        break;
                    case "FILE":
                    default:
                        this.SetFileCache(path);
                        break;
                }
            }

            if (!this.cacheSet)
            {
                this.SetMemoryCache();
            }
        }

        private void SetMemoryCache()
        {
            this.Cache = new MemoryTicketCache(this.Configuration, this.loggerFactory) { Refresh = this.Refresh };
        }

        private void SetLsaCache()
        {
            this.Cache = new LsaCredentialCache(this.Configuration, logger: this.loggerFactory);
        }

        private void SetFileCache(string cachePath)
        {
            if (this.Configuration.Defaults.CCacheType < 3)
            {
                throw new NotSupportedException(
                    $"A cache type of {this.Configuration.Defaults.CCacheType} is not supported. Only version 3 or higher is supported."
                );
            }

            CreateFilePath(cachePath);

            this.Cache = new Krb5TicketCache(cachePath, this.loggerFactory) { Version = this.Configuration.Defaults.CCacheType };
        }

        private static void CreateFilePath(string cachePath)
        {
            var path = Path.GetDirectoryName(cachePath);

            if (string.IsNullOrWhiteSpace(path) || Directory.Exists(path))
            {
                return;
            }

            Directory.CreateDirectory(path);
        }

        private static string TryFindReferralShortcut(KrbEncTgsRepPart encKdcRepPart)
        {
            var svrReferralPaData = encKdcRepPart?.EncryptedPaData?.MethodData?.FirstOrDefault(d => d.Type == PaDataType.PA_SVR_REFERRAL_INFO);

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
            var session = await this.GetServiceTicket(
                new RequestServiceTicket
                {
                    ServicePrincipalName = spn,
                    ApOptions = options,
                    S4uTarget = s4u,
                    S4uTicket = s4uTicket,
                    UserToUserTicket = u2uServerTicket
                },
                this.cancellation.Token
            ).ConfigureAwait(false);

            return session.ApReq;
        }

        public virtual void ImportCredential(ReadOnlyMemory<byte> krbCred)
        {
            this.ImportCredential(KrbCred.DecodeApplication(krbCred));
        }

        public virtual void ImportCredential(KrbCred krbCred)
        {
            if (krbCred is null)
            {
                throw new ArgumentNullException(nameof(krbCred));
            }

            var credPart = krbCred.Validate();

            for (var i = 0; i < krbCred.Tickets.Length; i++)
            {
                var ticket = krbCred.Tickets[i];
                var ticketInfo = credPart.TicketInfo[i];

                this.Cache.Add(TicketCacheEntry.ConvertKrbCredToCacheEntry(credPart, ticket, ticketInfo));
            }
        }

        private async Task Refresh(MemoryTicketCache.CacheEntry entry)
        {
            // optimistically try and refresh a cached ticket if it's renewable
            // however tickets that are already expired can't be renewed

            if (entry.IsExpired(this.Configuration.Defaults.ClockSkew))
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

            if (this.IsRenewable(entry, out KerberosClientCacheEntry ticket))
            {
                var cname = ticket.KdcResponse.CName.FullyQualifiedName;
                var sname = ticket.KdcResponse.Ticket.SName.FullyQualifiedName;

                this.logger.LogInformation("Ticket for {CName} to {SName} is renewing because it's expiring in {TTL}", cname, sname, entry.TimeToLive);

                await this.RenewTicket(sname).ConfigureAwait(false);
            }
        }

        private bool IsRenewable(MemoryTicketCache.CacheEntry entry, out KerberosClientCacheEntry ticket)
        {
            ticket = default;

            if (entry.Value is KerberosClientCacheEntry tick)
            {
                if (entry.TimeToLive <= TimeSpan.Zero || entry.TimeToLive > this.RenewTicketsThreshold)
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
            this.logger.LogInformation(
                "Requesting TGS for {SPN}; TGT Realm = {TGTRealm}; TGT Service = {TGTService}; S4U = {S4U}; S4UTicket = {S4UTicketSPN}; KDC Flags = {KDCFlags}",
                rst.ServicePrincipalName,
                tgtEntry.KdcResponse.CRealm,
                tgtEntry.KdcResponse.Ticket.SName.FullyQualifiedName,
                rst.S4uTarget,
                rst.S4uTicket?.SName?.FullyQualifiedName,
                rst.KdcOptions
            );

            var tgsReq = KrbTgsReq.CreateTgsReq(rst, tgtEntry.SessionKey, tgtEntry.KdcResponse, out KrbEncryptionKey sessionKey);

            this.logger.LogDebug(
                "TGT EType = {TGTEType}; TGS Session Key = {TGSEType}; PAData = {PADataTypes}",
                tgtEntry.SessionKey.EType,
                sessionKey.EType,
                tgsReq.PaData.Select(s => s.Type).ToArray()
            );

            var encodedTgs = tgsReq.EncodeApplication();

            cancellation.ThrowIfCancellationRequested();

            var tgsRep = await this.transport.SendMessage<KrbTgsRep>(
                rst.Realm,
                encodedTgs,
                cancellation
            ).ConfigureAwait(false);

            var entry = new KerberosClientCacheEntry
            {
                KdcResponse = tgsRep,
                SessionKey = sessionKey,
                Nonce = tgsReq.Body.Nonce
            };

            this.logger.LogInformation(
                "TGS-REP for {SPN}; CName = {CName}; CRealm = {CRealm}; PAData = {PADataTypes}",
                tgsRep.Ticket.SName.FullyQualifiedName,
                tgsRep.CName.FullyQualifiedName,
                tgsRep.CRealm,
                tgsRep.PaData?.Select(s => s.Type)?.ToArray()
            );

            return entry;
        }

        private KerberosClientCacheEntry CopyTicket(string spn)
        {
            var entry = this.Cache.GetCacheItem<KerberosClientCacheEntry>(spn);

            lock (this._syncTicketCache)
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
                spn = $"krbtgt/{this.DefaultDomain}";
            }

            var entry = this.CopyTicket(spn);

            var tgs = KrbTgsReq.CreateTgsReq(
                new RequestServiceTicket
                {
                    ServicePrincipalName = spn,
                    KdcOptions = ReconcileKdcFlags(this.KdcOptions, entry.Flags) | KdcOptions.Renew | KdcOptions.RenewableOk,
                    Realm = ResolveKdcTarget(entry)
                },
                entry.SessionKey,
                entry.KdcResponse,
                out KrbEncryptionKey subkey
            );

            var encodedTgs = tgs.EncodeApplication();

            var tgsRep = await this.transport.SendMessage<KrbTgsRep>(
                tgs.Body.Realm,
                encodedTgs
            ).ConfigureAwait(false);

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                subkey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.DecodeApplication(d)
            );

            this.CacheTgt(tgsRep, encKdcRepPart);
        }

        private void CacheTgt(KrbKdcRep kdcRep, KrbEncKdcRepPart encKdcRepPart)
        {
            var key = kdcRep.Ticket.SName.FullyQualifiedName;

            encKdcRepPart.Key.Usage = KeyUsage.EncTgsRepPartSessionKey;

            this.Cache.Add(new TicketCacheEntry
            {
                Key = key,
                Expires = encKdcRepPart.EndTime,
                RenewUntil = encKdcRepPart.RenewTill,
                Value = new KerberosClientCacheEntry
                {
                    SessionKey = encKdcRepPart.Key,
                    Flags = encKdcRepPart.Flags,
                    KdcResponse = kdcRep,

                    AuthTime = encKdcRepPart.AuthTime,
                    StartTime = encKdcRepPart.StartTime ?? DateTimeOffset.MinValue,
                    EndTime = encKdcRepPart.EndTime,
                    RenewTill = encKdcRepPart.RenewTill,
                    SName = encKdcRepPart.SName
                }
            });
        }

        private async Task RequestTgt(KerberosCredential credential)
        {
            var asReqMessage = KrbAsReq.CreateAsReq(credential, this.AuthenticationOptions);

            var asReq = asReqMessage.EncodeApplication();

            this.logger.LogTrace(
                "Attempting AS-REQ. UserName = {UserName}; Domain = {Domain}; Nonce = {Nonce}",
                credential.UserName,
                credential.Domain,
                asReqMessage.Body.Nonce
            );

            var asRep = await this.transport.SendMessage<KrbAsRep>(credential.Domain, asReq).ConfigureAwait(false);

            var decrypted = credential.DecryptKdcRep(
                asRep,
                KeyUsage.EncAsRepPart,
                d => this.DecodeEncKdcRepPart<KrbEncAsRepPart>(d)
            );

            VerifyNonces(asReqMessage.Body.Nonce, decrypted.Nonce);

            this.DefaultDomain = credential.Domain;

            this.CacheTgt(asRep, decrypted);
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
                this.logger.LogDebug(
                    "EncPart expected to be {ExpectedType} and is actually {ActualType}",
                    typeof(T).Name,
                    repPart.GetType().Name
                );

                if (this.AuthenticationOptions.HasFlag(AuthenticationOptions.RepPartCompatible) || repPart is T)
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

        private static IKerberosTransport[] CreateTransports(ILoggerFactory logger)
        {
            return new IKerberosTransport[]
            {
                new TcpKerberosTransport(logger),
                new UdpKerberosTransport(logger),
                new HttpsKerberosTransport(logger)
            };
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    if (this.Cache is IDisposable cache)
                    {
                        cache.Dispose();
                    }

                    this.transport.Dispose();

                    this.clientLoggingScope.Dispose();
                    this.cancellation.Dispose();
                }

                this.disposed = true;
            }
        }

        ~KerberosClient()
        {
            this.Dispose(false);
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
