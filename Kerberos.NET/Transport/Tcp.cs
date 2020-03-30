using Kerberos.NET.Crypto;
using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal static class Tcp
    {
        public static ReadOnlyMemory<byte> FormatKerberosMessageStream(ReadOnlyMemory<byte> message)
        {
            var kerbMessage = new Memory<byte>(new byte[message.Length + 4]);

            Endian.ConvertToBigEndian(message.Length, kerbMessage.Slice(0, 4));

            message.CopyTo(kerbMessage.Slice(4));

            return kerbMessage;
        }

        public static async Task<ReadOnlyMemory<byte>> ReadFromStream(int messageSize, NetworkStream stream, CancellationToken cancellation)
        {
            var response = new byte[messageSize];

            int read = 0;

            while (read < response.Length)
            {
                read += await stream.ReadAsync(
                    response,
                    read,
                    response.Length - read,
                    cancellation
                );
            }

            return response;
        }
    }
}
