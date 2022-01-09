using Kerberos.NET.Client;
using Kerberos.NET.Credentials;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace Kerberos.NET.CommandLine
{
    internal class PingResult
    {
        public KrbAsReq AsReq { get; set; }

        public KrbAsRep AsRep { get; set; }

        public KrbError Error { get; set; }
    }

    internal static class KerberosPing
    {
        public static async Task<PingResult> Ping(KerberosCredential credential, KerberosClient client, ILoggerFactory logger = null)
        {
            credential.Configuration = client.Configuration;

            var asReqMessage = KrbAsReq.CreateAsReq(credential, AuthenticationOptions.Renewable);

            var asReq = asReqMessage.EncodeApplication();

            var transport = new KerberosTransportSelector(
                new IKerberosTransport[]
                {
                    new TcpKerberosTransport(logger),
                    new UdpKerberosTransport(logger),
                    new HttpsKerberosTransport(logger)
                },
                client.Configuration,
                logger
            )
            {
                ConnectTimeout = TimeSpan.FromSeconds(5)
            };

            var result = new PingResult { AsReq = asReqMessage };

            try
            {
                result.AsRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);
            }
            catch (KerberosProtocolException pex)
            {
                result.Error = pex.Error;
            }

            return result;
        }
    }
}
