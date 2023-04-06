using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Configuration;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Client
{
    public class LsaCredentialCache : TicketCacheBase
    {
        private readonly HashSet<string> SuccessfulGets = new(StringComparer.OrdinalIgnoreCase);

        private const int ERROR_NO_SUCH_LOGON_SESSION = 0x520;
        private const int STATUS_NO_TRUST_SAME_ACCOUNT = 0x6FB;

        private readonly LsaInterop lsa;

        public LsaCredentialCache(Krb5Config config, LsaInterop lsa = null, ILoggerFactory logger = null)
            : base(config, logger)
        {
            this.lsa = lsa ?? LsaInterop.Connect();
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            lsa.Dispose();
        }

        public override ValueTask<bool> AddAsync(TicketCacheEntry entry)
        {
            if (this.Add(entry))
            {
                return new ValueTask<bool>(true);
            }

            return new ValueTask<bool>(false);
        }

        public override bool Add(TicketCacheEntry entry)
        {
            if (entry.Value is KerberosClientCacheEntry cacheEntry)
            {
                var cred = KrbCred.WrapTicket(
                    cacheEntry.KdcResponse.Ticket,
                    new KrbCredInfo
                    {
                        Key = cacheEntry.SessionKey,
                        AuthTime = cacheEntry.AuthTime,
                        EndTime = cacheEntry.EndTime,
                        Flags = cacheEntry.Flags,
                        PName = cacheEntry.KdcResponse.CName,
                        Realm = cacheEntry.KdcResponse.CRealm,
                        RenewTill = cacheEntry.RenewTill,
                        SName = cacheEntry.KdcResponse.Ticket.SName,
                        SRealm = cacheEntry.KdcResponse.Ticket.Realm,
                        StartTime = cacheEntry.StartTime
                    }
                );

                lsa.ImportCredential(cred);
            }

            return true;
        }

        public override ValueTask<bool> ContainsAsync(TicketCacheEntry entry) => new(false);

        public override bool Contains(TicketCacheEntry entry) => false;

        public override IEnumerable<object> GetAll() => lsa.GetTicketCache().Cast<object>();

        public override ValueTask<object> GetCacheItemAsync(string key, string container = null) => new(this.GetCacheItem(key, container));

        public override object GetCacheItem(string key, string container = null)
        {
            if (key.EndsWith("/"))
            {
                key = key.Substring(0, key.Length - 1);
            }

            if (KrbPrincipalName.FromString(key).IsKrbtgt())
            {
                // We want LSA to deal with krbtgt. We do not want it.
                // LSA giving us the krbtgt ticket is a security vulnerability waiting to happen.
                return null;
            }

            KrbCred ticket = GetTicket(key);

            var credInfo = ticket.Validate();

            for (var i = 0; i < ticket.Tickets.Length; i++)
            {
                var entry = TicketCacheEntry.ConvertKrbCredToCacheEntry(credInfo, ticket.Tickets[i], credInfo.TicketInfo[i]);

                if (entry.Value != null)
                {
                    return entry.Value;
                }
            }

            return null;
        }

        private KrbCred GetTicket(string key)
        {
            return TryWithKerberosCatch(
                () => this.TryGetTicketOrThrow(key),
                k =>
                {
                    if (!this.SuccessfulGets.Contains(key))
                    {
                        throw k;
                    }

                    this.SuccessfulGets.Clear();

                    this.PurgeTickets();

                    return this.TryGetTicketOrThrow(key);
                }
            );
        }

        private KrbCred TryGetTicketOrThrow(string key)
        {
            var possiblePrincipalNames = new List<string> { key };

            if (this.Configuration.TryFindRealmHint(key, out string referral) && !string.IsNullOrWhiteSpace(referral))
            {
                possiblePrincipalNames.Add($"{key}@{referral}");
            }

            Exception lastException = null;

            foreach (var spn in possiblePrincipalNames)
            {
                var ticket = TryWithKerberosCatch(
                    () => this.GetTicketOrThrow(spn),
                    k =>
                    {
                        lastException = k;
                        return null;
                    }
                );

                if (ticket != null)
                {
                    return ticket;
                }
            }

            throw lastException ?? PrincipalUnknownException();
        }

        private static Exception PrincipalUnknownException()
            => new KerberosProtocolException(new KrbError { ErrorCode = KerberosErrorCode.KDC_ERR_S_PRINCIPAL_UNKNOWN });

        private KrbCred GetTicketOrThrow(string key)
        {
            var ticket = TryWithKerberosCatch(() => lsa.GetTicket(key)) ?? throw PrincipalUnknownException();

            this.SuccessfulGets.Add(key);

            return ticket;
        }

        private static T TryWithKerberosCatch<T>(Func<T> func, Func<KerberosProtocolException, T> error = null)
        {
            try
            {
                return func();
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == ERROR_NO_SUCH_LOGON_SESSION)
            {
                throw new InvalidOperationException(ex.Message);
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == STATUS_NO_TRUST_SAME_ACCOUNT)
            {
                throw PrincipalUnknownException();
            }
            catch (KerberosProtocolException kex)
            {
                if (error is null)
                {
                    throw;
                }

                return error(kex);
            }
        }

        public override T GetCacheItem<T>(string key, string container = null)
        {
            var result = this.GetCacheItem(key, container);

            if (result is T value)
            {
                return value;
            }

            return default;
        }

        public override async ValueTask<T> GetCacheItemAsync<T>(string key, string container = null)
        {
            var result = await this.GetCacheItemAsync(key, container).ConfigureAwait(false);

            return result != null ? (T)result : default;
        }

        public override void PurgeTickets() => lsa.PurgeTicketCache();
    }
}
