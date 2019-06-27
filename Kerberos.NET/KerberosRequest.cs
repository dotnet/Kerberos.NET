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
            var token = NegotiationRequest?.MechToken?.InnerContextToken;

            var messageType = token.MessageType;
            var authEType = token.Authenticator?.EType;
            var realm = token.Ticket?.Realm;
            var ticketEType = token.Ticket?.EncPart?.EType;
            var nameType = token.Ticket?.SName?.NameType;

            var snames = token.Ticket?.SName?.FullyQualifiedName;

            return $"Mechanism: {mech} | " +
                   $"MessageType: {messageType} | " +
                   $"SName: {nameType}, {snames} | " +
                   $"Realm: {realm} | " +
                   $"Ticket EType: {ticketEType} | " +
                   $"Auth EType: {authEType}";
        }
    }
}
