using System;
using System.Buffers.Binary;
using System.Security.Cryptography.Asn1;
using Kerberos.NET.Transport;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Used to describe how a KDC proxy message has encoded the internal message
    /// </summary>
    public enum KdcProxyMessageMode
    {
        /// <summary>
        /// Indicates the message does not include the length prefix.
        /// This is often used by clients that encode messages using the UDP form.
        /// </summary>
        NoPrefix = 0,

        /// <summary>
        /// Indicates the message does include the length prefix.
        /// This is often used by clients that encode messages using the TCP form.
        /// </summary>
        IncludeLengthPrefix = 1
    }

    public partial class KdcProxyMessage
    {
        /// <summary>
        /// Wraps a standard KDC message into a proxy message
        /// </summary>
        /// <param name="message">The message to wrap</param>
        /// <param name="domain">The optional domain hint for downstream processing</param>
        /// <param name="hint">A DC location hint for downstream processing</param>
        /// <param name="mode">The encoding mode which indicates whether the message should include the length prefix or not</param>
        /// <returns>Returns a formed KDC Message</returns>
        public static KdcProxyMessage WrapMessage(
            ReadOnlyMemory<byte> message,
            string domain = null,
            DcLocatorHint? hint = null,
            KdcProxyMessageMode mode = KdcProxyMessageMode.IncludeLengthPrefix
        )
        {
            var proxyMessage = new KdcProxyMessage()
            {
                TargetDomain = domain,
                DcLocatorHint = hint
            };

            if (mode == KdcProxyMessageMode.NoPrefix)
            {
                proxyMessage.KerbMessage = message;
            }
            else
            {
                proxyMessage.KerbMessage = Tcp.FormatKerberosMessageStream(message);
            }

            return proxyMessage;
        }

        /// <summary>
        /// Unwraps a proxy-encoded message for further processing
        /// </summary>
        /// <returns>Returns the unwrapped message</returns>
        public ReadOnlyMemory<byte> UnwrapMessage()
        {
            return UnwrapMessage(out _);
        }

        /// <summary>
        /// Unwraps a proxy-encoded message for further processing
        /// </summary>
        /// <param name="mode">Indicates whether the proxy message includes the length prefix or not</param>
        /// <returns>Returns the unwrapped message</returns>
        public ReadOnlyMemory<byte> UnwrapMessage(out KdcProxyMessageMode mode)
        {
            var prefix = KerbMessage.Slice(0, 4).AsLong();
            var message = KerbMessage;

            if (prefix != KerbMessage.Length - 4)
            {
                var possibleMessageType = KrbMessage.DetectMessageType(KerbMessage);

                if (!possibleMessageType.IsValidMessageType())
                {
                    throw new InvalidOperationException(
                        $"Proxy message length {prefix} doesn't match actual message length {message.Length}"
                    );
                }

                mode = KdcProxyMessageMode.NoPrefix;
            }
            else
            {
                message = KerbMessage.Slice(4);
                mode = KdcProxyMessageMode.IncludeLengthPrefix;
            }

            return message;
        }

        /// <summary>
        /// Attempt to decode a stream of bytes into a <see cref="KdcProxyMessage"/>
        /// </summary>
        /// <param name="encoded">The message to decode</param>
        /// <param name="decoded">The decoded message</param>
        /// <returns>Returns true if it was successfully decoded, otherwise returns false</returns>
        public static bool TryDecode(ReadOnlyMemory<byte> encoded, out KdcProxyMessage decoded)
        {
            decoded = null;

            var reader = new AsnReader(encoded, AsnEncodingRules.DER);

            var tag = reader.PeekTag();

            if (tag != Asn1Tag.Sequence)
            {
                return false;
            }

            try
            {
                Decode(reader, Asn1Tag.Sequence, out decoded);
                reader.ThrowIfNotEmpty();
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}
