// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// A utility class to detect message properties
    /// </summary>
    public static class KrbMessage
    {
        /// <summary>
        /// Determine if the message is a Kerberos Type
        /// </summary>
        /// <param name="message">The message to examine</param>
        /// <returns>Returns the possible <see cref="MessageType"/></returns>
        public static MessageType DetectMessageType(ReadOnlyMemory<byte> message)
            => DetectMessageType(message, out _);

        public static MessageType DetectMessageType(ReadOnlyMemory<byte> message, out int length)
        {
            var tag = PeekTag(message, out length);

            return DetectMessageType(tag);
        }

        internal static MessageType DetectMessageType(Asn1Tag tag)
        {
            if (tag.TagClass != TagClass.Application)
            {
                throw new KerberosProtocolException($"Unknown incoming tag {tag}");
            }

            var messageType = (MessageType)tag.TagValue;

            return messageType;
        }

        internal static Asn1Tag PeekTag(ReadOnlyMemory<byte> request, out int length)
        {
            AsnReader reader = new(request, AsnEncodingRules.DER);

            var tag = reader.ReadTagAndLength(out int? maybeLength, out int _);

            length = maybeLength ?? 0;

            return tag;
        }
    }
}
