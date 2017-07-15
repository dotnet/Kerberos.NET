using Syfuhs.Security.Kerberos.Crypto;
using Syfuhs.Security.Kerberos.Entities;
using System.Linq;
using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos
{
    public class KerberosRequest
    {
        private static readonly Dictionary<EncryptionType, Func<KrbApReq, DecryptedData>> Decryptors
            = new Dictionary<EncryptionType, Func<KrbApReq, DecryptedData>>();

        public static void RegisterDecryptor(EncryptionType type, Func<KrbApReq, DecryptedData> func)
        {
            Decryptors[type] = func;
        }

        static KerberosRequest()
        {
            RegisterDecryptor(EncryptionType.RC4_HMAC_NT, (token) => new RC4DecryptedData(token));
            RegisterDecryptor(EncryptionType.RC4_HMAC_NT_EXP, (token) => new RC4DecryptedData(token));
        }

        public KerberosRequest(byte[] data)
        {
            var element = new Asn1Element(data);

            for (var i = 0; i < element.Count; i++)
            {
                var child = element[i];

                switch (child.ContextSpecificTag)
                {
                    case 0:
                        NegotiationToken = new NegTokenInit(child[0]);
                        break;
                    case MechType.ContextTag:
                        MechType = new MechType(child.AsString());
                        break;
                    case 110:
                        Request = new KrbApReq(child[0]);
                        break;
                }
            }
        }

        public MechType MechType { get; private set; }

        public NegTokenInit NegotiationToken { get; private set; }

        public KrbApReq Request { get; private set; }

        public static KerberosRequest Parse(byte[] data)
        {
            var ticket = new KerberosRequest(data);

            return ticket;
        }

        public DecryptedData Decrypt(KeyTable keytab)
        {
            if (NegotiationToken != null)
            {
                return DecryptNegotiate(NegotiationToken, keytab);
            }

            if (Request != null)
            {
                return DecryptKerberos(Request, keytab);
            }

            return null;
        }

        private DecryptedData DecryptKerberos(KrbApReq request, KeyTable keytab)
        {
            return Decrypt(request, keytab);
        }

        private static DecryptedData DecryptNegotiate(NegTokenInit negotiationToken, KeyTable keytab)
        {
            var token = negotiationToken?.MechToken?.InnerContextToken;

            return Decrypt(token, keytab);
        }

        private static DecryptedData Decrypt(KrbApReq token, KeyTable keytab)
        {
            if (token?.Ticket?.EncPart == null)
            {
                return null;
            }

            DecryptedData decryptor = null;

            Func<KrbApReq, DecryptedData> func = null;

            if (Decryptors.TryGetValue(token.Ticket.EncPart.EType, out func) && func != null)
            {
                decryptor = func(token);
            }

            if (decryptor != null)
            {
                decryptor.Decrypt(keytab);
            }

            return decryptor;
        }

        public override string ToString()
        {
            var mech = MechType?.Mechanism;
            var messageType = NegotiationToken?.MechToken?.InnerContextToken?.MessageType;
            var authEType = NegotiationToken?.MechToken?.InnerContextToken?.Authenticator?.EType;
            var realm = NegotiationToken?.MechToken?.InnerContextToken?.Ticket?.Realm;
            var ticketEType = NegotiationToken?.MechToken?.InnerContextToken?.Ticket?.EncPart?.EType;
            var nameType = NegotiationToken?.MechToken?.InnerContextToken?.Ticket?.SName?.NameType;

            var names = "";
            var snames = NegotiationToken?.MechToken?.InnerContextToken?.Ticket?.SName?.Names;

            if (snames?.Any() ?? false)
            {
                names = string.Join(",", snames);
            }

            return $"Mechanism: {mech} | MessageType: {messageType} | SName: {nameType}, {names} | Realm: {realm} | Ticket EType: {ticketEType} | Auth EType: {authEType}";
        }
    }
}
