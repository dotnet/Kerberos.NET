using Syfuhs.Security.Kerberos.Crypto;
using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Syfuhs.Security.Kerberos.Entities
{
    public class RC4DecryptedData : DecryptedData
    {
        private readonly KrbApReq token;
        private readonly byte[] decryptingKey;

        public RC4DecryptedData(KrbApReq token, byte[] decryptingKey)
        {
            this.token = token;
            this.decryptingKey = decryptingKey;
        }

        private readonly byte[] baseKey;
        public RC4DecryptedData(KrbApReq token, byte[] decryptingKey, byte[] baseKey)
        {
            this.token = token;
            this.decryptingKey = decryptingKey;
            this.baseKey = baseKey;
        }
        
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

            byte[] salt = new byte[4];
            salt[0] = (byte)(usage & 0xff);
            salt[1] = (byte)((usage >> 8) & 0xff);
            salt[2] = (byte)((usage >> 16) & 0xff);
            salt[3] = (byte)((usage >> 24) & 0xff);
            return salt;
        }

        private const int HashSize = 16;
        private const int ConfounderSize = 8;

        public override void Decrypt()
        {
            var baseKey = this.baseKey;
            if (this.decryptingKey != null && this.decryptingKey.Length > 0)
            {
                baseKey = MD4(decryptingKey);
            }

            var ciphertext = token.Ticket.EncPart.Cipher;

            byte[] output = Decrypt(baseKey, ciphertext, KeyUsage.KU_TICKET);

            Ticket = new EncTicketPart(new Asn1Element(output));

            var decryptedAuthenticator = Decrypt(
                Ticket.EncryptionKey,
                token.Authenticator.Cipher,
                KeyUsage.KU_AP_REQ_AUTHENTICATOR
            );

            Authenticator = new Authenticator(new Asn1Element(decryptedAuthenticator));
        }

        private static byte[] Decrypt(byte[] k1, byte[] ciphertext, KeyUsage keyType)
        {
            // get the salt using key usage
            byte[] salt = GetSalt((int)keyType);

            // compute K2 using K1
            byte[] k2 = HMAC(k1, salt);

            byte[] checksum = new byte[HashSize];
            Buffer.BlockCopy(ciphertext, 0, checksum, 0, HashSize);

            byte[] k3 = HMAC(k2, checksum);

            byte[] ciphertextOffset = new byte[ciphertext.Length - HashSize];

            Buffer.BlockCopy(ciphertext, HashSize, ciphertextOffset, 0, ciphertextOffset.Length);

            //0 + HashSize, ciphertext.Length - HashSize
            byte[] plaintext = RC4.Decrypt(k3, ciphertextOffset);

            byte[] calculatedHmac = HMAC(k2, plaintext);

            bool invalidChecksum = false;

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

            byte[] output = new byte[plaintext.Length - ConfounderSize];
            Buffer.BlockCopy(plaintext, ConfounderSize, output, 0, output.Length);
            return output;
        }

        internal static byte[] HMAC(string password, byte[] data)
        {
            var key = MD4(password);

            return HMAC(key, data);
        }

        private static byte[] HMAC(byte[] key, byte[] data)
        {
            using (HMACMD5 hmac = new HMACMD5(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        private static byte[] MD4(byte[] key)
        {
            return new MD4().ComputeHash(key);
        }

        private static byte[] MD4(string password)
        {
            return new MD4().ComputeHash(Encoding.Unicode.GetBytes(password));
        }
    }
}
