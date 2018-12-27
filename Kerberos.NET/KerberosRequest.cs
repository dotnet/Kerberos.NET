using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.Linq;
using System;

namespace Kerberos.NET
{
    [Obsolete("Switch to MessageParser.Parse*()")]
    public class KerberosRequest
    {
        public static void RegisterDecryptor(EncryptionType type, Func<KrbApReq, DecryptedData> func)
        {
            ContextToken.RegisterDecryptor(type, func);
        }

        private readonly ContextToken negotiate;

        public KerberosRequest(byte[] data)
        {
            negotiate = MessageParser.ParseContext(data);
        }

        public MechType MechType { get { return negotiate.MechType; } }

        public NegTokenInit NegotiationRequest
        {
            get
            {
                var negToken = negotiate as NegotiateContextToken;

                return negToken?.NegotiationToken;
            }
        }

        public KrbApReq Request
        {
            get
            {
                var negToken = negotiate as NegotiateContextToken;

                return negToken?.NegotiationToken?.MechToken?.InnerContextToken;
            }
        }

        public static KerberosRequest Parse(byte[] data)
        {
            var ticket = new KerberosRequest(data);

            return ticket;
        }

        public DecryptedData Decrypt(KeyTable keytab)
        {
            return negotiate.Decrypt(keytab);
        }

        public override string ToString()
        {
            var mech = MechType?.Mechanism;
            var messageType = NegotiationRequest?.MechToken?.InnerContextToken?.MessageType;
            var authEType = NegotiationRequest?.MechToken?.InnerContextToken?.Authenticator?.EType;
            var realm = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.Realm;
            var ticketEType = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.EncPart?.EType;
            var nameType = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.SName?.NameType;

            var names = "";
            var snames = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.SName?.Names;

            if (snames?.Any() ?? false)
            {
                names = string.Join(",", snames);
            }

            return $"Mechanism: {mech} | MessageType: {messageType} | SName: {nameType}, {names} | Realm: {realm} | Ticket EType: {ticketEType} | Auth EType: {authEType}";
        }
    }
}
