using Kerberos.NET.Asn1;
using System;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public interface IKerberosTransport
    {
        bool TransportFailed { get; set; }

        KerberosTransportException LastError { get; set; }

        Task<T> SendMessage<T>(string domain, IAsn1Encoder req)
            where T : IAsn1Encoder, new();

        Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> req)
            where T : IAsn1Encoder, new();
    }
}
