using Kerberos.NET.Dns;
using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    public interface ITcpSocket : IDisposable
    {
        bool Connected { get; }

        DateTimeOffset LastRelease { get; }
        
        TimeSpan ReceiveTimeout { get; set; }
        
        TimeSpan SendTimeout { get; set; }
        
        string TargetName { get; }

        Task<bool> Connect(DnsRecord target, TimeSpan connectTimeout);
        
        void Free();
        
        NetworkStream GetStream();
    }
}