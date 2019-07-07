using Kerberos.NET.Credentials;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Transport;
using System;
using System.Threading.Tasks;

namespace Kerberos.NET.Client
{
    public enum AuthenticationResult
    {
        Accepted
    }

    [Flags]
    public enum AuthenticationOptions
    {
        PreAuthenticate = 1 << 0,
        IncludePacRequest = 1 << 2
    }

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

        //private readonly ITicketCache ticketCache;

        public KerberosClient()
            : this(new UdpKerberosTransport(), new TcpKerberosTransport())
        {
        }

        private const AuthenticationOptions DefaultAuthentication = AuthenticationOptions.IncludePacRequest;

        private readonly KerberosTransportSelector transport;

        public KerberosClient(params IKerberosTransport[] transports)
        {
            transport = new KerberosTransportSelector(transports);
        }



        private KrbKdcRep tgt;
        private KrbEncryptionKey tgtSessionKey;

        public async Task<AuthenticationResult> Authenticate(
            KerberosCredential credential,
            AuthenticationOptions options = DefaultAuthentication)
        {
            int preauthAttempts = 0;

            do
            {
                try
                {
                    await RequestTicket(credential, options);

                    return AuthenticationResult.Accepted;
                }
                catch (KerberosProtocolException pex)
                {
                    if (++preauthAttempts > 3 || pex.Error.ErrorCode != KerberosErrorCode.KDC_ERR_PREAUTH_REQUIRED)
                    {
                        throw;
                    }

                    credential.IncludePreAuthenticationHints(pex.Error.DecodePreAuthentication());

                    options |= AuthenticationOptions.PreAuthenticate;
                }
            }
            while (true);
        }

        public async Task<KrbApReq> GetTicket(string spn)
        {
            KrbTgsReq tgs = KrbTgsReq.CreateTgsReq(spn, tgtSessionKey, tgt);

            var tgtTicket = tgt.Ticket.Application;

            var choice = await transport.SendMessage<KrbTgsRep>(
                tgtTicket.Realm,
                tgs.EncodeAsApplication()
            );

            var encKdcRepPart = choice.Response?.EncPart.Decrypt(
                d => KrbEncTgsRepPart.Decode(d),
                tgtSessionKey.AsKey(),
                KeyUsage.KU_ENC_TGS_REP_PART_SUBKEY
            );

            var authenticatorKey = encKdcRepPart.EncTgsRepPart.Key.AsKey();

            var ticket = choice.Response.Ticket;

            var authenticator = new KrbAuthenticator
            {
                CName = choice.Response.CName,
                CTime = DateTimeOffset.UtcNow,
                Cusec = 0,
                Realm = ticket.Application.Realm,
                SequenceNumber = KerberosConstants.GetNonce(),
                Subkey = null,
                AuthenticatorVersionNumber = 5
            };

            var apReq = new KrbApReq
            {
                Ticket = choice.Response.Ticket,
                Authenticator = KrbEncryptedData.Encrypt(
                    authenticator.EncodeAsApplication().ToArray(),
                    authenticatorKey,
                    authenticatorKey.EncryptionType,
                    KeyUsage.KU_AP_REQ_AUTHENTICATOR
                )
            };

            return apReq;
        }

        private async Task RequestTicket(KerberosCredential credential, AuthenticationOptions options)
        {
            var asReq = KrbAsReq.CreateAsReq(options, credential);

            var asRep = await transport.SendMessage<KrbAsRep>(credential.Domain, asReq.EncodeAsApplication());

            var kdcRep = asRep.Response;

            var decrypted = DecryptAsRep(kdcRep, credential);

            CacheTgt(kdcRep, decrypted.EncAsRepPart);
        }

        private void CacheTgt(KrbKdcRep kdcRep, KrbEncKdcRepPart decrypted)
        {
            tgt = kdcRep;
            tgtSessionKey = decrypted.Key;
        }

        private static KrbEncAsRepPart DecryptAsRep(KrbKdcRep asRep, KerberosCredential credential)
        {
            var key = credential.CreateKey();

            return asRep.EncPart.Decrypt(d => KrbEncAsRepPart.Decode(d), key, Crypto.KeyUsage.KU_ENC_AS_REP_PART);
        }
    }
}
