// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Transport
{
    public abstract class KerberosTransportBase : IKerberosTransport, IDisposable
    {
        private const int DefaultKerberosPort = 88;

        private readonly string kdc;

        private static readonly Random Random = new Random();

        private readonly ConcurrentDictionary<string, DnsRecord> negativeCache
            = new ConcurrentDictionary<string, DnsRecord>();

        protected KerberosTransportBase(string kdc = null)
        {
            this.kdc = kdc;
        }

        private static readonly ConcurrentDictionary<string, DnsRecord> DomainCache
            = new ConcurrentDictionary<string, DnsRecord>();

        private bool disposedValue;

        public virtual bool TransportFailed { get; set; }

        public virtual KerberosTransportException LastError { get; set; }

        public bool Enabled { get; set; }

        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(2);

        public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public int MaximumAttempts { get; set; } = 30;

        protected static T Decode<T>(ReadOnlyMemory<byte> response)
            where T : IAsn1ApplicationEncoder<T>, new()
        {
            if (KrbError.CanDecode(response))
            {
                var error = KrbError.DecodeApplication(response);

                if (error.ErrorCode == KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG)
                {
                    throw new KerberosTransportException(error);
                }

                throw new KerberosProtocolException(error);
            }

            return new T().DecodeAsApplication(response);
        }

        public virtual Task<TResponse> SendMessage<TRequest, TResponse>(
            string domain,
            IAsn1ApplicationEncoder<TRequest> req,
            CancellationToken cancellation = default
        )
            where TResponse : IAsn1ApplicationEncoder<TResponse>, new()
        {
            if (req == null)
            {
                throw new ArgumentNullException(nameof(req));
            }

            return this.SendMessage<TResponse>(domain, req.EncodeApplication());
        }

        public abstract Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        )
            where T : IAsn1ApplicationEncoder<T>, new();

        protected virtual DnsRecord QueryDomain(string lookup)
        {
            return DomainCache.AddOrUpdate(
                lookup, // find SRV by domain name in cache
                dn => this.QueryDns(dn, null), // if it doesn't exist in cache just query and add
                (dn, existing) => existing.Purge ? this.QueryDns(dn, existing) : existing // if it already exists check if its ignored and replace
            );
        }

        private DnsRecord QueryDns(string lookup, DnsRecord ignored)
        {
            if (!string.IsNullOrWhiteSpace(this.kdc))
            {
                var split = this.kdc.Split(':');

                var record = new DnsRecord
                {
                    Target = split[0]
                };

                if (split.Length > 1)
                {
                    record.Port = int.Parse(split[1], CultureInfo.InvariantCulture);
                }
                else
                {
                    record.Port = DefaultKerberosPort;
                }

                return record;
            }

            var results = this.Query(lookup).Where(r => r.Type == DnsRecordType.SRV);

            if (ignored != null && ignored.Ignore)
            {
                // can get here through expiration, and we don't actually want to negative cache
                // something that has just expired because it could still genuinely be good

                this.negativeCache[ignored.Target] = ignored;
            }

            results = results.Where(s => !this.negativeCache.TryGetValue(s.Target, out DnsRecord record) || record.Expired);

            var weighted = results.GroupBy(r => r.Weight).OrderBy(r => r.Key).OrderByDescending(r => r.Sum(a => a.Canonical.Count())).FirstOrDefault();

            var rand = Random.Next(0, weighted?.Count() ?? 0);

            var srv = weighted?.ElementAtOrDefault(rand);

            if (srv == null)
            {
                throw new KerberosTransportException($"Cannot locate SRV record for {lookup}");
            }

            if (srv.Port <= 0)
            {
                srv.Port = DefaultKerberosPort;
            }

            return srv;
        }

        protected virtual IEnumerable<DnsRecord> Query(string lookup)
        {
            return DnsQuery.QuerySrv(lookup);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!this.disposedValue)
            {
                this.disposedValue = true;
            }
        }

        public void Dispose()
        {
            this.Dispose(disposing: true);

            GC.SuppressFinalize(this);
        }
    }
}