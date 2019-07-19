using System;
using System.Net;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public class ListenerOptions
    {
        public EndPoint ListeningOn { get; set; }

        public bool SupportTcp { get; set; } = true;

        public bool SupportUdp { get; set; } = false;

        public int QueueLength { get; set; } = 1000;

        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(30);

        public int MaxReadBufferSize { get; set; } = 1024 * 1024;

        public int MaxWriteBufferSize { get; set; } = 64 * 1024;

        public ILogger Log { get; set; }

        public string DefaultRealm { get; set; }

        public bool IsDebug { get; set; }

        public Func<string, Task<IRealmService>> RealmLocator { get; set; }
    }
}
