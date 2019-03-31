using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET.Crypto
{
    public class RC4DecryptedData : DecryptedData
    {
        private readonly KrbApReq token;
        private readonly RC4Transformer transformer;

        private static readonly MD4Encryptor MD4Encryptor = new MD4Encryptor();

        public RC4DecryptedData(KrbApReq token)
        {
            this.token = token;
            this.transformer = new RC4Transformer(MD4Encryptor);
        }

        public override EncryptionType EType => EncryptionType.RC4_HMAC_NT;

        public override void Decrypt(KeyTable keytab)
        {
            SName = token.Ticket.SName;

            var ciphertext = token.Ticket.EncPart.Cipher;

            var key = keytab.GetKey(token);

            var decryptedTicket = Decrypt(key, ciphertext, KeyUsage.KU_TICKET);

            Ticket = new EncTicketPart().Decode(new Asn1Element(decryptedTicket));

            var decryptedAuthenticator = Decrypt(
                new KerberosKey(Ticket.Key.RawKey),
                token.Authenticator.Cipher,
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator().Decode(new Asn1Element(decryptedAuthenticator));
        }

        private byte[] Decrypt(KerberosKey key, byte[] ciphertext, KeyUsage keyType)
        {
            return transformer.Decrypt(ciphertext, key, keyType);
        }
    }

    internal class MD4Encryptor : IEncryptor
    {
        public int BlockSize { get { throw new NotSupportedException(); } }

        public int KeyInputSize { get { throw new NotSupportedException(); } }

        public int KeySize { get { throw new NotSupportedException(); } }

        public void Decrypt(byte[] ke, byte[] iv, byte[] tmpEnc)
        {
            throw new NotSupportedException();
        }

        public void Encrypt(byte[] key, byte[] ki)
        {
            throw new NotSupportedException();
        }

        public void Encrypt(byte[] ke, byte[] iv, byte[] tmpEnc)
        {
            throw new NotSupportedException();
        }

        public byte[] String2Key(KerberosKey key)
        {
            return MD4(key.PasswordBytes);
        }

        private static byte[] MD4(byte[] key)
        {
            return new MD4().ComputeHash(key);
        }
    }
}
