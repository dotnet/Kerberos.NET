using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;

namespace Kerberos.NET
{
    [Obsolete("Switch to MessageParser.Parse*()")]
    public class KerberosRequest
    {
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
                var negToken = negotiate as KerberosContextToken;

                return negToken?.KrbApReq;
            }
        }

        public static KerberosRequest Parse(byte[] data)
        {
            var ticket = new KerberosRequest(data);

            return ticket;
        }

        public DecryptedKrbApReq Decrypt(KeyTable keytab)
        {
            return negotiate.DecryptApReq(keytab);
        }

        public override string ToString()
        {
            var mech = MechType?.Mechanism;
            var messageType = NegotiationRequest?.MechToken?.InnerContextToken?.MessageType;
            var authEType = NegotiationRequest?.MechToken?.InnerContextToken?.Authenticator?.EType;
            var realm = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.Realm;
            var ticketEType = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.EncPart?.EType;
            var nameType = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.SName?.NameType;

            var snames = NegotiationRequest?.MechToken?.InnerContextToken?.Ticket?.SName?.FullyQualifiedName;

            return $"Mechanism: {mech} | MessageType: {messageType} | SName: {nameType}, {snames} | Realm: {realm} | Ticket EType: {ticketEType} | Auth EType: {authEType}";
        }
    }
}
