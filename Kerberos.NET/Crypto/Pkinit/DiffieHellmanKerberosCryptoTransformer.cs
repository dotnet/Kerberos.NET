using System;

namespace Kerberos.NET.Crypto
{
    public class DiffieHellmanKerberosCryptoTransformer : KerberosCryptoTransformer
    {
        public override int ChecksumSize => throw new NotImplementedException();

        public override int BlockSize => throw new NotImplementedException();

        public override int KeySize => throw new NotImplementedException();

        public override ReadOnlyMemory<byte> Decrypt(ReadOnlyMemory<byte> cipher, KerberosKey key, KeyUsage usage)
        {
            throw new NotImplementedException();
        }

        public override ReadOnlyMemory<byte> Encrypt(ReadOnlyMemory<byte> data, KerberosKey key, KeyUsage usage)
        {
            throw new NotImplementedException();
        }

        public virtual ReadOnlyMemory<byte> String2Key(
            ReadOnlySpan<byte> sharedSecret,
            int length,
            ReadOnlySpan<byte> clientNonce = default,
            ReadOnlySpan<byte> serverNonce = default
        )
        {
            var key = new Memory<byte>(new byte[length]);
            var sha1 = CryptoPal.Platform.Sha1();

            var x = Concat(sharedSecret, clientNonce, serverNonce);

            var fill = sha1.ComputeHash(Concat(0, x));

            var position = 0;
            var count = 0;

            for (var i = 0; i < length; i++)
            {
                int index;

                if (position < fill.Length)
                {
                    index = position;
                    position++;
                }
                else
                {
                    count++;
                    fill = sha1.ComputeHash(Concat((byte)count, x));
                    index = position = 0;

                    position++;
                }

                key.Span[i] = fill.Span[index];
            }

            return key;
        }

        private ReadOnlySpan<byte> Concat(ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> clientNonce, ReadOnlySpan<byte> serverNonce)
        {
            var span = new Span<byte>(new byte[sharedSecret.Length + clientNonce.Length + serverNonce.Length]);

            sharedSecret.CopyTo(span);
            clientNonce.CopyTo(span.Slice(sharedSecret.Length));
            serverNonce.CopyTo(span.Slice(sharedSecret.Length + clientNonce.Length));

            return span;
        }

        private ReadOnlySpan<byte> Concat(byte count, ReadOnlySpan<byte> x)
        {
            var result = new Span<byte>(new byte[x.Length + 1]);

            result[0] = count;
            x.CopyTo(result.Slice(1));

            return result;
        }

        public override ReadOnlyMemory<byte> String2Key(KerberosKey key)
        {
            var dhKey = key.GetKey();

            var sha1 = CryptoPal.Platform.Sha1();

            throw new NotImplementedException();
        }
    }
}
