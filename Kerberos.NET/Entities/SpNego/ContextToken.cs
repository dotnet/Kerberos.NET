// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Kerberos.NET.Crypto;

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
            if (token?.Ticket == null)
            {
                return null;
            }

            var decryptedApReq = new DecryptedKrbApReq(token);

            decryptedApReq.Decrypt(keytab);

            return decryptedApReq;
        }

        internal static ContextToken Parse(GssApiToken token)
        {
            var mechType = token.ThisMech.Value;

            if (!KnownMessageTypes.TryGetValue(mechType, out Func<GssApiToken, ContextToken> tokenFunc))
            {
                throw new UnknownMechTypeException(mechType);
            }

            return tokenFunc(token);
        }
    }
}