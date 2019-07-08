using Kerberos.NET.Asn1;
using Kerberos.NET.Client;
using Kerberos.NET.Dns;
using Kerberos.NET.Entities;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public abstract class KerberosTransportBase : IKerberosTransport
    {
        private const int DefaultKerberosPort = 88;

        private static readonly ConcurrentDictionary<string, DnsRecord> DomainCache = new ConcurrentDictionary<string, DnsRecord>();

        protected ILogger Logger { get; set; }

        public virtual bool TransportFailed { get; set; }

        public virtual KerberosTransportException LastError { get; set; }

        protected void Log(string log)
        {
            Logger?.WriteLine(KerberosLogSource.Client, log);
        }

        protected static T Decode<T>(byte[] response) where T : IAsn1Encoder, new()
        {
            if (KrbError.CanDecode(response))
            {
                var error = KrbErrorChoice.Decode(response).Error;

                if (error.ErrorCode == KerberosErrorCode.KRB_ERR_RESPONSE_TOO_BIG)
                {
                    throw new KerberosTransportException(error);
                }

                throw new KerberosProtocolException(error);
            }

            return (T)new T().Decode(response);
        }

        public virtual Task<T> SendMessage<T>(string domain, IAsn1Encoder req)
            where T : IAsn1Encoder, new()
        {
            return SendMessage<T>(domain, req.Encode().AsMemory());
        }

        public abstract Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req)
            where T : IAsn1Encoder, new();

        protected DnsRecord QueryDomain(string lookup)
        {
            return DomainCache.GetOrAdd(lookup, d => QueryDns(d));
        }

        private DnsRecord QueryDns(string lookup)
        {
            var results = Query(lookup);

            var srv = results.FirstOrDefault(s => s.Type == DnsRecordType.SRV);

            if (srv == null)
            {
                throw new KerberosTransportException($"Cannot locate UDP SRV record for {lookup}");
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
    }
}
