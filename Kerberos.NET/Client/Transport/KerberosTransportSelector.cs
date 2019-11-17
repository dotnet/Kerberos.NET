using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    public class KerberosTransportSelector : KerberosTransportBase
    {
        public KerberosTransportSelector(IEnumerable<IKerberosTransport> transports)
        {
            this.Transports = transports;
        }

        public IEnumerable<IKerberosTransport> Transports { get; }

        public override async Task<T> SendMessage<T>(
            string domain,
            ReadOnlyMemory<byte> encoded,
            CancellationToken cancellation = default
        )
        {
            // basic logic should be 
            // foreach transport 
            // if (canSendMessage) { trySend }
            // if try = fail for transport reasons move on to next
            // if try = fail or protocol reasons, throw and bail

            foreach (var transport in Transports.Where(t => t.Enabled && !t.TransportFailed))
            {
                transport.ConnectTimeout = ConnectTimeout;

                try
                {
                    return await transport.SendMessage<T>(domain, encoded, cancellation);
                }
                catch (KerberosTransportException tex)
                {
                    transport.TransportFailed = true;
                    transport.LastError = LastError = tex;
                }
            }

            throw LastError ?? new KerberosTransportException("No transport could be used to send the message");
        }
    }
}
