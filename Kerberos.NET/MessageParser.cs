// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.SpNego;

namespace Kerberos.NET
{
    public static class MessageParser
    {
        // Messages can be of any form and usually resemble a token.
        //
        // Message = [Token | GSS-API-Message]
        //
        // The average message is a token wrapped in GSS-API goo.
        // A GSS-API message looks approximately something like this:
        //
        // GSS-API-Message =
        // {
        //     Oid tokenType,
        //     Token token
        // }
        //
        // Token = [NegotiateToken | KerberosToken | NtlmToken]
        //
        // Negotiate tokens are messages containing a request or response
        //
        // NegotiateToken = [Request | Response]
        //
        // Requests contain a list of supported token (Mech) types
        // And optimistically inclue a token in the format of the first type
        //
        // Request =
        // {
        //      Oid[] tokenTypes,
        //      Token optimisticToken
        // }

        public static ContextToken ParseContext(ReadOnlyMemory<byte> data)
        {
            return Parse<ContextToken>(data);
        }

        public static NegotiateContextToken ParseNegotiate(ReadOnlyMemory<byte> data)
        {
            return Parse<NegotiateContextToken>(data);
        }

        public static KerberosContextToken ParseKerberos(ReadOnlyMemory<byte> data)
        {
            return Parse<KerberosContextToken>(data);
        }

        public static T Parse<T>(ReadOnlyMemory<byte> data)
        {
            return (T)Parse(data);
        }

        public static object Parse(ReadOnlyMemory<byte> data)
        {
            if (ParsedNonGssApiToken(data, out ContextToken token))
            {
                return token;
            }

            var gss = GssApiToken.Decode(data);

            return ContextToken.Parse(gss);
        }

        private static bool ParsedNonGssApiToken(ReadOnlyMemory<byte> data, out ContextToken token)
        {
            // A caller may try and pass a token that isn't wrapped by GSS-API semantics
            // We should try and detect what it is and return that instead of treating
            // it like GSS data
            //
            // We'll check if it's NTLM, NegoEx, or Kerberos
            // Otherwise bail and try letting GssApiToken sort it out

            // are we an NTLM token?

            if (NtlmMessage.CanReadNtlmMessage(data))
            {
                token = new NtlmContextToken(data: data);
                return true;
            }

            // are we a NegoEx token?

            if (NegotiateExtension.CanDecode(data))
            {
                token = new NegoExContextToken(data);
                return true;
            }

            // are we a Kerberos ticket?

            if (KrbApChoice.CanDecode(data))
            {
                token = new KerberosContextToken(data: data);
                return true;
            }

            // we don't know what we are. Maybe we're GSS so figure it out later.

            token = null;

            return false;
        }
    }
}