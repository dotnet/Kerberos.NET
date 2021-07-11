// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal static class Tcp
    {
        public static async Task WriteAsync(this NetworkStream stream, ReadOnlyMemory<byte> message, CancellationToken cancellation)
        {
            if (!MemoryMarshal.TryGetArray(message, out ArraySegment<byte> segment))
            {
                segment = new ArraySegment<byte>(message.ToArray());
            }

            await stream.WriteAsync(segment.Array, 0, message.Length, cancellation).ConfigureAwait(false);
        }

        public static byte[] FormatKerberosMessageStream(ReadOnlyMemory<byte> message)
        {
            var messageBytes = new byte[message.Length + 4];

            FormatKerberosMessageStream(message, messageBytes);

            return messageBytes;
        }

        public static void FormatKerberosMessageStream(ReadOnlyMemory<byte> message, Memory<byte> formattedMessage)
        {
            BinaryPrimitives.WriteInt32BigEndian(formattedMessage.Span.Slice(0, 4), message.Length);

            message.CopyTo(formattedMessage.Slice(4));
        }

        public static async Task ReadFromStream(Memory<byte> readResponse, NetworkStream stream, CancellationToken cancellation, TimeSpan readTimeout)
        {
            if (!MemoryMarshal.TryGetArray(readResponse, out ArraySegment<byte> segment))
            {
                throw new InvalidOperationException("Cannot get backing array");
            }

            using (var timeout = new CancellationTokenSource(readTimeout))
            using (var cancel = CancellationTokenSource.CreateLinkedTokenSource(cancellation, timeout.Token))
            {
                int read = 0;

                while (read < readResponse.Length)
                {
                    read += await stream.ReadAsync(
                        segment.Array,
                        read,
                        readResponse.Length - read,
                        cancel.Token
                    ).ConfigureAwait(false);
                }
            }
        }

        public static async Task<ReadOnlyMemory<byte>> ReadFromStream(
            int messageSize,
            NetworkStream stream,
            CancellationToken cancellation,
            TimeSpan readTimeout
        )
        {
            var bytes = new byte[messageSize];

            await ReadFromStream(bytes, stream, cancellation, readTimeout);

            return bytes;
        }
    }
}
