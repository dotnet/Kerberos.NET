// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kerberos.NET.Asn1;
using Kerberos.NET.Configuration;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.ChangePassword;
using Microsoft.Extensions.Logging;

namespace Kerberos.NET.Transport
{
    public abstract class KerberosTransportBase : IKerberosTransport2, IDisposable
    {
        private static readonly Random Random = new Random();

        protected KerberosTransportBase(ILoggerFactory logger)
        {
            this.ClientRealmService = new ClientDomainService(logger);
        }

        private bool disposedValue;

        public virtual bool TransportFailed { get; set; }

        public virtual KerberosTransportException LastError { get; set; }

        public bool Enabled { get; set; }

        public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(2);

        public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(10);

        public int MaximumAttempts { get; set; } = 30;

        public virtual ClientDomainService ClientRealmService { get; }

        public Guid ScopeId { get; set; }

        public Krb5Config Configuration
        {
            get => this.ClientRealmService.Configuration;
            set => this.ClientRealmService.Configuration = value;
        }

        protected static void CheckError(ReadOnlyMemory<byte> response)
        {
            if (KrbError.CanDecode(response))
            {
                var error = KrbError.DecodeApplication(response);

                if (error.ErrorCode == KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG)
                {
                    throw new KerberosTransportException(error);
                }
                else if (error.ErrorCode == KerberosErrorCode.KDC_ERR_WRONG_REALM)
                {
                    throw new KerberosTransportException(error);
                }

                throw new KerberosProtocolException(error);
            }
        }

        protected static T Decode<T>(ReadOnlyMemory<byte> response)
            where T : IAsn1ApplicationEncoder<T>, new()
        {
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

        protected virtual Task<IEnumerable<DnsRecord>> LocateKdc(string domain, string servicePrefix)
        {
            return this.ClientRealmService.LocateKdc(domain, servicePrefix);
        }

        protected virtual Task<IEnumerable<DnsRecord>> LocateKpasswd(string domain, string servicePrefix)
        {
            return this.ClientRealmService.LocateKpasswd(domain, servicePrefix);
        }

        public async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        )
            where T : IAsn1ApplicationEncoder<T>, new()
        {
            var response = await SendMessage(domain, req, cancellation);

            CheckError(response);

            return Decode<T>(response);
        }

        public virtual async Task<KrbChangePasswdRep> SendMessageChangePassword(
            string domain,
            KrbChangePasswdReq msg,
            CancellationToken cancellation = default
        )
        {
            if (msg == null)
            {
                throw new ArgumentNullException(nameof(msg));
            }

            var response = await SendMessageChangePassword(domain, msg.Encode(), cancellation);

            CheckError(response);

            return new KrbChangePasswdRep(response);
        }

        public abstract Task<ReadOnlyMemory<byte>> SendMessage(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation);

        public virtual Task<ReadOnlyMemory<byte>> SendMessageChangePassword(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation)
        {
            throw new NotSupportedException();
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

        protected virtual async Task<DnsRecord> LocatePreferredKdc(string domain, string servicePrefix)
        {
            var results = await this.LocateKdc(domain, servicePrefix);
            return SelectedPreferredInstance(domain, servicePrefix, results, ClientDomainService.DefaultKerberosPort);
        }

        protected virtual async Task<DnsRecord> LocatePreferredKpasswd(string domain, string servicePrefix)
        {
            var results = await this.LocateKpasswd(domain, servicePrefix);
            return SelectedPreferredInstance(domain, servicePrefix, results, ClientDomainService.DefaultKpasswdPort);
        }

        protected virtual DnsRecord SelectedPreferredInstance(string domain, string servicePrefix, IEnumerable<DnsRecord> results, int defaultPort)
        {
            results = results.Where(r => r.Name.StartsWith(servicePrefix));

            var rand = Random.Next(0, results?.Count() ?? 0);

            var srv = results?.ElementAtOrDefault(rand);

            if (srv == null)
            {
                throw new KerberosTransportException($"Cannot locate SRV record for {domain}");
            }

            if (srv.Port <= 0)
            {
                srv.Port = defaultPort;
            }

            return srv;
        }
    }
}
