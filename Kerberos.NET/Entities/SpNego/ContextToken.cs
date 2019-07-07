using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;

namespace Kerberos.NET.Entities
{
    public abstract class ContextToken
    {
        private static readonly Dictionary<string, Func<GssApiToken, ContextToken>> KnownMessageTypes
            = new Dictionary<string, Func<GssApiToken, ContextToken>>
            {
                { MechType.SPNEGO, e => new NegotiateContextToken(e) },
                { MechType.NEGOEX, e => new NegotiateContextToken(e) },
                { MechType.KerberosV5, e => new KerberosContextToken(e) },
                { MechType.KerberosV5Legacy, e => new KerberosContextToken(e) },
                { MechType.KerberosUser2User, e => new KerberosUser2UserContextToken(e) }
            };

        public abstract DecryptedKrbApReq DecryptApReq(KeyTable keys);

        protected static DecryptedKrbApReq DecryptApReq(KrbApReq token, KeyTable keytab)
        {
            if (token.Ticket.Application == null)
            {
                return null;
            }

            DecryptedKrbApReq decryptedApReq = null;

            var etype = token.Ticket.Application?.EncryptedPart.EType;

            var decryptor = CryptographyService.CreateTransform(etype.Value);

            if (decryptor != null)
            {
                decryptedApReq = new DecryptedKrbApReq(token, decryptor);

                decryptedApReq.Decrypt(keytab);
            }

            return decryptedApReq;
        }

        internal static ContextToken Parse(GssApiToken token)
        {
            var mechType = token.ThisMech.Value;

            if (string.IsNullOrWhiteSpace(mechType))
            {
                throw new UnknownMechTypeException();
            }

            if (!KnownMessageTypes.TryGetValue(mechType, out Func<GssApiToken, ContextToken> tokenFunc))
            {
                throw new UnknownMechTypeException(mechType);
            }

            return tokenFunc(token);
        }
    }
}
