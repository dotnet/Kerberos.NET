using Kerberos.NET.Crypto;
using System;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Entities
{
    public partial class KdcProxyMessage
    {
        public static KdcProxyMessage WrapMessage(ReadOnlyMemory<byte> message, string domain = null, DcLocatorHint? hint = null)
        {
            var kerbMessage = new Memory<byte>(new byte[message.Length + 4]);

            Endian.ConvertToBigEndian(message.Length, kerbMessage.Slice(0, 4));

            message.CopyTo(kerbMessage.Slice(4));

            return new KdcProxyMessage()
            {
                KerbMessage = kerbMessage,
                TargetDomain = domain,
                DcLocatorHint = hint
            };
        }

        public ReadOnlyMemory<byte> UnwrapMessage()
        {
            var length = KerbMessage.Slice(0, 4).AsLong();
            var message = KerbMessage.Slice(4);

            if (length != message.Length)
            {
                throw new InvalidOperationException(
                    $"Proxy message length {length} doesn't match actual message length {message.Length}"
                );
            }

            return message;
        }

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
