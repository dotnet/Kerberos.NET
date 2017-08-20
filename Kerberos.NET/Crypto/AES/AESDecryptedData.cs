using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    public abstract class AESDecryptedData : DecryptedData
    {
        private readonly KrbApReq token;

        protected AESDecryptedData(KrbApReq token)
        {
            this.token = token;
        }

        public override EncryptionType EType => Token?.Ticket?.EncPart?.EType ?? EncryptionType.NULL;

        protected abstract KerberosEncryptor Decryptor { get; }

        protected KrbApReq Token { get { return token; } }

        public override void Decrypt(KeyTable keytab)
        {
            var key = keytab.GetKey(Token);

            var decrypted = Decryptor.Decrypt(
                Token.Ticket.EncPart.Cipher,
                key.WithPrincipalName(
                    token.Ticket.SName
                ),
                KeyUsage.KU_TICKET
            );

            DecodeTicket(decrypted);
        }

        private void DecodeTicket(byte[] output)
        {
            Ticket = new EncTicketPart(new Asn1Element(output));

            var decryptedAuthenticator = Decryptor.Decrypt(
                Token.Authenticator.Cipher,
                new KerberosKey(
                    Ticket.EncryptionKey
                ),
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator(new Asn1Element(decryptedAuthenticator));
        }
    }
}