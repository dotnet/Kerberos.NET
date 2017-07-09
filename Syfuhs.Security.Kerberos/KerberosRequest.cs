using Syfuhs.Security.Kerberos.Crypto;
using Syfuhs.Security.Kerberos.Entities;
using System.Linq;
using System;
using System.Collections.Generic;

namespace Syfuhs.Security.Kerberos
{
    public class KerberosRequest
    {
        private static readonly Dictionary<EncryptionType, Func<KrbApReq, KerberosKey, DecryptedData>> Decryptors
            = new Dictionary<EncryptionType, Func<KrbApReq, KerberosKey, DecryptedData>>();

        public static void RegisterDecryptor(EncryptionType type, Func<KrbApReq, KerberosKey, DecryptedData> func)
        {
            Decryptors[type] = func;
        }

        static KerberosRequest()
        {
            RegisterDecryptor(EncryptionType.RC4_HMAC_NT, (token, key) => new RC4DecryptedData(token, key));
            RegisterDecryptor(EncryptionType.RC4_HMAC_NT_EXP, (token, key) => new RC4DecryptedData(token, key));
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

        public DecryptedData Decrypt(KerberosKey key)
        {
            if (NegotiationToken != null)
            {
                return DecryptNegotiate(NegotiationToken, key);
            }

            if (Request != null)
            {
                return DecryptKerberos(Request, key);
            }

            return null;
        }

        private DecryptedData DecryptKerberos(KrbApReq request, KerberosKey key)
        {
            return Decrypt(key, request);
        }

        private static DecryptedData DecryptNegotiate(NegTokenInit negotiationToken, KerberosKey key)
        {
            var token = negotiationToken?.MechToken?.InnerContextToken;

            return Decrypt(key, token);
        }

        private static DecryptedData Decrypt(KerberosKey key, KrbApReq token)
        {
            if (token?.Ticket?.EncPart == null)
            {
                return null;
            }

            DecryptedData decryptor = null;

            Func<KrbApReq, KerberosKey, DecryptedData> func = null;

            if (Decryptors.TryGetValue(token.Ticket.EncPart.EType, out func) && func != null)
            {
                decryptor = func(token, key);
            }

            if (decryptor != null)
            {
                decryptor.Decrypt();
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
