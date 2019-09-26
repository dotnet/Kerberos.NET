using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public class KerberosTransportSelector : KerberosTransportBase
    {
        private readonly IEnumerable<IKerberosTransport> transports;

        public KerberosTransportSelector(IEnumerable<IKerberosTransport> transports, ILogger logger = null)
        {
            this.transports = transports;

            Logger = logger ?? new DebugLogger();
        }

        public override ProtocolType Protocol => ProtocolType.Unspecified;

        public IEnumerable<IKerberosTransport> Transports => transports;

        public override async Task<T> SendMessage<T>(string domain, ReadOnlyMemory<byte> encoded)
        {
            // basic logic should be 
            // foreach transport 
            // if (canSendMessage) { trySend }
            // if try = fail for transport reasons move on to next
            // if try = fail or protocol reasons, throw and bail

            foreach (var transport in transports.Where(t => t.Enabled && !t.TransportFailed))
            {
                try
                {
                    return await transport.SendMessage<T>(domain, encoded);
                }
                catch (KerberosTransportException tex)
                {
                    transport.TransportFailed = true;
                    transport.LastError = LastError = tex;
                }
            }

            throw LastError ?? new KerberosTransportException("No transport could be used to send the message");
        }

        public override void Dispose()
        {
            foreach (var transport in transports)
            {
                if (transport is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }

            base.Dispose();
        }
    }
}
