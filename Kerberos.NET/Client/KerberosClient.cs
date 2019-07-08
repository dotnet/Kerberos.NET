using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    public class KerberosClient
    {
        // - transport -> TCP/UDP/injected transport handler
        //
        // - KDC resolution -> specify DC name or use DNS resolution?
        //                  -> DC resolver tries DC by locator instead?
        //
        // - authenticate -> as-rep => TGT
        //                   -> request PAC?
        //                   -> include pre-auth by default?
        //                   -> automatically retry with pre-auth added?
        //                   -> request ticket for self to get local authz?
        //                   -> cache TGT/cache service ticket?

        public KerberosClient()
            : this(new UdpKerberosTransport(), new TcpKerberosTransport())
        {
        }

        private const AuthenticationOptions DefaultAuthentication = 
            AuthenticationOptions.IncludePacRequest |
            AuthenticationOptions.RenewableOk |
            AuthenticationOptions.Canonicalize |
            AuthenticationOptions.Renewable |
            AuthenticationOptions.Forwardable;

        private readonly KerberosTransportSelector transport;

        public KerberosClient(params IKerberosTransport[] transports)
        {
            transport = new KerberosTransportSelector(transports);
        }

        private KrbKdcRep tgt;
        private KrbEncryptionKey tgtSessionKey;

        public AuthenticationOptions Options { get; set; } = DefaultAuthentication;

        public async Task Authenticate(KerberosCredential credential)
        {
            credential.Validate();

            int preauthAttempts = 0;

            do
            {
                try
                {
                    await RequestTgt(credential);
                    break;
                }
                catch (KerberosProtocolException pex)
                {
                    if (++preauthAttempts > 3 || pex.Error.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        throw;
                    }

                    credential.IncludePreAuthenticationHints(pex.Error.DecodePreAuthentication());

                    Options |= AuthenticationOptions.PreAuthenticate;
                }
            }
            while (true);
        }

        public async Task<KrbApReq> GetServiceTicket(string spn)
        {
            var tgs = KrbTgsReq.CreateTgsReq(spn, tgtSessionKey, tgt);

            var choice = await transport.SendMessage<KrbTgsRep>(
                tgs.TgsReq.Body.Realm,
                tgs.EncodeAsApplication()
            );

            var tgsRep = choice.Response;

            var encKdcRepPart = tgsRep.EncPart.Decrypt(
                tgtSessionKey.AsKey(),
                KeyUsage.EncTgsRepPartSubSessionKey,
                d => KrbEncTgsRepPart.Decode(d)
            );

            var authenticatorKey = encKdcRepPart.EncTgsRepPart.Key.AsKey();

            return KrbApReq.CreateAsReq(tgsRep, authenticatorKey);
        }

        private async Task RequestTgt(KerberosCredential credential)
        {
            var asReq = KrbAsReq.CreateAsReq(credential, Options).EncodeAsApplication();

            var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq);

            var decrypted = DecryptAsRep(asRep.Response, credential);

            CacheTgt(asRep.Response, decrypted.EncAsRepPart);
        }

        private void CacheTgt(KrbKdcRep kdcRep, KrbEncKdcRepPart decrypted)
        {
            tgt = kdcRep;
            tgtSessionKey = decrypted.Key;
        }

        private static KrbEncAsRepPart DecryptAsRep(KrbKdcRep asRep, KerberosCredential credential)
        {
            var key = credential.CreateKey();

            return asRep.EncPart.Decrypt(key, KeyUsage.EncAsRepPart, d => KrbEncAsRepPart.Decode(d));
        }
    }
}
