using Kerberos.NET.Asn1;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public interface IKerberosTransport
    {
        bool TransportFailed { get; set; }

        KerberosTransportException LastError { get; set; }

        bool Enabled { get; set; }

        TimeSpan ConnectTimeout { get; set; }

        TimeSpan SendTimeout { get; set; }

        TimeSpan ReceiveTimeout { get; set; }

        int MaximumAttempts { get; set; }

        Task<TResponse> SendMessage<TRequest, TResponse>(
            string domain,
            IAsn1ApplicationEncoder<TRequest> req,
            CancellationToken cancellation = default
        ) where TResponse : IAsn1ApplicationEncoder<TResponse>, new();

        Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> req,
            CancellationToken cancellation = default
        ) where T : IAsn1ApplicationEncoder<T>, new();
    }
}
