using Syfuhs.Security.Kerberos.Crypto;
using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos
{
    public class KerberosRequest
    {
        public KerberosRequest(byte[] data)
        {
            var element = new Asn1Element(data);

            MechType = new MechType(element[0].AsString());
            NegotiationToken = new NegTokenInit(element[1][0]);
        }

        public MechType MechType { get; private set; }

        public NegTokenInit NegotiationToken { get; private set; }

        public static KerberosRequest Parse(byte[] data)
        {
            var ticket = new KerberosRequest(data);

            return ticket;
        }

        public DecryptedData Decrypt(byte[] key)
        {
            DecryptedData decryptor = null;

            switch (NegotiationToken.MechToken.InnerContextToken.Ticket.EncPart.EType)
            {
                case EncryptionType.RC4_HMAC_NT:
                case EncryptionType.RC4_HMAC_NT_EXP:
                    decryptor = new RC4DecryptedData(NegotiationToken.MechToken.InnerContextToken, key);
                    break;
                case EncryptionType.AES128_CTS_HMAC_SHA1_96:
                case EncryptionType.AES256_CTS_HMAC_SHA1_96:
                    break;
            }

            if (decryptor != null)
            {
                decryptor.Decrypt();
            }

            return decryptor;
        }

        public override string ToString()
        {
            var mech = MechType.Mechanism;
            var messageType = NegotiationToken.MechToken.InnerContextToken.MessageType;
            var authEType = NegotiationToken.MechToken.InnerContextToken.Authenticator.EType;
            var realm = NegotiationToken.MechToken.InnerContextToken.Ticket.Realm;
            var ticketEType = NegotiationToken.MechToken.InnerContextToken.Ticket.EncPart.EType;
            var names = string.Join(",", NegotiationToken.MechToken.InnerContextToken.Ticket.SName.Names);
            var nameType = NegotiationToken.MechToken.InnerContextToken.Ticket.SName.NameType;

            return $"Mechanism: {mech} | MessageType: {messageType} | SName: {nameType}, {names} | Realm: {realm} | Ticket EType: {ticketEType} | Auth EType: {authEType}";
        }
    }
}
