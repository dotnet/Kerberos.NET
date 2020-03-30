using Kerberos.NET.Dns;
using System;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    public interface ISocketPool : IDisposable
    {
        int MaxPoolSize { get; set; }

        TimeSpan ScavengeWindow { get; set; }

        Task<ITcpSocket> Request(DnsRecord target, TimeSpan connectTimeout);
    }
}