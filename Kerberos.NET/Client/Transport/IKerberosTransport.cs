using Kerberos.NET.Asn1;
using System;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public interface IKerberosTransport
    {
        bool TransportFailed { get; set; }

        KerberosTransportException LastError { get; set; }

        Task<TResponse> SendMessage<TRequest, TResponse>(string domain, IAsn1ApplicationEncoder<TRequest> req)
            where TResponse : IAsn1ApplicationEncoder<TResponse>, new();

        Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req)
            where T : IAsn1ApplicationEncoder<T>, new();
    }
}
