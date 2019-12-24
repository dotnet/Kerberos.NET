using Kerberos.NET.Entities;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Threading.Tasks;

namespace Kerberos.NET.Server
{
    public class ListenerOptions
    {
        public EndPoint ListeningOn { get; set; }

        public int QueueLength { get; set; } = 1000;

        public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(30);

        public TimeSpan AcceptTimeout { get; set; } = TimeSpan.FromSeconds(30);

        public int MaxReadBufferSize { get; set; } = 1024 * 1024;

        public int MaxWriteBufferSize { get; set; } = 64 * 1024;

        public ILoggerFactory Log { get; set; }

        public string DefaultRealm { get; set; }

        public bool IsDebug { get; set; }

        public Func<string, Task<IRealmService>> RealmLocator { get; set; }

        public Func<Guid> NextScopeId { get; set; } = KerberosConstants.GetRequestActivityId;

        public bool ProxyEnabled { get; set; } = true;
    }
}
