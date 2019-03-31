using Kerberos.NET.Entities;

#pragma warning disable S101 // Types should be named in camel case

namespace Kerberos.NET.Crypto
{
    public abstract class AESDecryptedData : DecryptedData
    {
        protected AESDecryptedData(KrbApReq token)
        {
            this.Token = token;
        }

        public override EncryptionType EType => Token?.Ticket?.EncPart?.EType ?? EncryptionType.NULL;

        protected abstract KerberosCryptoTransformer Transformer { get; }

        protected KrbApReq Token { get; }

        public override void Decrypt(KeyTable keytab)
        {
            SName = Token.Ticket.SName;

            var key = keytab.GetKey(Token);

            var kerbKey = key.WithPrincipalName(
                Token.Ticket.SName
            );

            var decrypted = Transformer.Decrypt(
                Token.Ticket.EncPart.Cipher,
                kerbKey,
                KeyUsage.KU_TICKET
            );

            DecodeTicket(decrypted);
        }

        private void DecodeTicket(byte[] decryptedTicket)
        {
            Ticket = new EncTicketPart().Decode(new Asn1Element(decryptedTicket));

            var decryptedAuthenticator = Transformer.Decrypt(
                Token.Authenticator.Cipher,
                new KerberosKey(
                    Ticket.Key.RawKey
                ),
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator().Decode(new Asn1Element(decryptedAuthenticator));
        }
    }
}