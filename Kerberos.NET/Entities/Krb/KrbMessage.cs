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
        {
            var tag = PeekTag(message);

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

        internal static Asn1Tag PeekTag(ReadOnlyMemory<byte> request)
        {
            AsnReader reader = new AsnReader(request, AsnEncodingRules.DER);

            return reader.PeekTag();
        }
    }
}
