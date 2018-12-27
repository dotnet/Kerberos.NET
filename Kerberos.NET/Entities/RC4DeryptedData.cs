using Kerberos.NET.Crypto;
using System;
using System.Security;

namespace Kerberos.NET.Entities
{
    public class RC4DecryptedData : DecryptedData
    {
        private readonly KrbApReq token;
        
        public RC4DecryptedData(KrbApReq token)
        {
            this.token = token;
        }

        public override EncryptionType EType => EncryptionType.RC4_HMAC_NT;

        private static byte[] GetSalt(int usage)
        {
            switch (usage)
            {
                case 3:
                    usage = 8;
                    break;
                case 9:
                    usage = 8;
                    break;
                case 23:
                    usage = 13;
                    break;
            }

            var salt = new byte[4]
            {
                (byte)(usage & 0xff),
                (byte)((usage >> 8) & 0xff),
                (byte)((usage >> 16) & 0xff),
                (byte)((usage >> 24) & 0xff)
            };

            return salt;
        }

        private const int HashSize = 16;
        private const int ConfounderSize = 8;

        private static readonly IEncryptor MD4Encryptor = new MD4Encryptor();

        public override void Decrypt(KeyTable keytab)
        {
            var ciphertext = token.Ticket.EncPart.Cipher;

            var key = keytab.GetKey(token);
            
            var decryptedTicket = Decrypt(key.GetKey(MD4Encryptor), ciphertext, KeyUsage.KU_TICKET);

            Ticket = new EncTicketPart(new Asn1Element(decryptedTicket));

            var decryptedAuthenticator = Decrypt(
                Ticket.Key.RawKey,
                token.Authenticator.Cipher,
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator(new Asn1Element(decryptedAuthenticator));
        }

        private static byte[] Decrypt(byte[] k1, byte[] ciphertext, KeyUsage keyType)
        {
            var salt = GetSalt((int)keyType);

            var k2 = KerberosHash.HMACMD5(k1, salt);

            var checksum = new byte[HashSize];

            Buffer.BlockCopy(ciphertext, 0, checksum, 0, HashSize);

            var k3 = KerberosHash.HMACMD5(k2, checksum);

            var ciphertextOffset = new byte[ciphertext.Length - HashSize];

            Buffer.BlockCopy(ciphertext, HashSize, ciphertextOffset, 0, ciphertextOffset.Length);

            var plaintext = RC4.Decrypt(k3, ciphertextOffset);

            var calculatedHmac = KerberosHash.HMACMD5(k2, plaintext);

            var invalidChecksum = false;

            if (calculatedHmac.Length >= HashSize)
            {
                for (var i = 0; i < HashSize; i++)
                {
                    if (calculatedHmac[i] != ciphertext[i])
                    {
                        invalidChecksum = true;
                    }
                }
            }

            if (invalidChecksum)
            {
                throw new SecurityException("Invalid Checksum");
            }

            var output = new byte[plaintext.Length - ConfounderSize];

            Buffer.BlockCopy(plaintext, ConfounderSize, output, 0, output.Length);

            return output;
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
            return KerberosHash.MD4(key.PasswordBytes);
        }
    }
}
