using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos.Crypto
{
    public abstract class AESDecryptedData : DecryptedData
    {
        private readonly KrbApReq token;
        private readonly KerberosKey decryptingKey;

        protected AESDecryptedData(KrbApReq token, KerberosKey decryptingKey)
        {
            this.token = token;
            this.decryptingKey = decryptingKey;
        }

        protected abstract KerberosEncryptor Decryptor { get; }

        protected KrbApReq Token { get { return token; } }

        protected KerberosKey DecryptingKey { get { return decryptingKey; } }

        protected void DecodeTicket(byte[] output)
        {
            Ticket = new EncTicketPart(new Asn1Element(output));

            var decryptedAuthenticator = Decryptor.Decrypt(
                Token.Authenticator.Cipher,
                new KerberosKey(Ticket.EncryptionKey),
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator(new Asn1Element(decryptedAuthenticator));
        }
    }
}