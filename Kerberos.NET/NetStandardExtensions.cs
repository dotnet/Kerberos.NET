using System;
using System.Buffers;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace Kerberos.NET
{
#if NETSTANDARD2_0
    public static class StreamExtensions
    {
        public static ValueTask WriteAsync(this Stream stream,
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default (CancellationToken))
        {
            ArraySegment<byte> segment;
            if (MemoryMarshal.TryGetArray<byte>(buffer, out segment))
                return new ValueTask(stream.WriteAsync(segment.Array, segment.Offset, segment.Count, cancellationToken));
            byte[] numArray = ArrayPool<byte>.Shared.Rent(buffer.Length);
            buffer.Span.CopyTo((Span<byte>) numArray);
            return new ValueTask(stream.FinishWriteAsync(stream.WriteAsync(numArray, 0, buffer.Length, cancellationToken), numArray));
        }

        internal static async Task FinishWriteAsync(this Stream stream, Task writeTask, byte[] localBuffer)
        {
            try
            {
                await writeTask.ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(localBuffer, false);
            }
        }
        
        internal static ValueTask<int> ReadAsync(this Stream stream,
            Memory<byte> buffer,
            CancellationToken cancellationToken = default (CancellationToken))
        {
            ArraySegment<byte> segment;
            if (MemoryMarshal.TryGetArray<byte>((ReadOnlyMemory<byte>) buffer, out segment))
                return new ValueTask<int>(stream.ReadAsync(segment.Array, segment.Offset, segment.Count, cancellationToken));
            byte[] numArray = ArrayPool<byte>.Shared.Rent(buffer.Length);
            return FinishReadAsync(stream.ReadAsync(numArray, 0, buffer.Length, cancellationToken), numArray, buffer);

            async ValueTask<int> FinishReadAsync(
                Task<int> readTask,
                byte[] localBuffer,
                Memory<byte> localDestination)
            {
                int num;
                try
                {
                    int length = await readTask.ConfigureAwait(false);
                    new Span<byte>(localBuffer, 0, length).CopyTo(localDestination.Span);
                    num = length;
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(localBuffer, false);
                }
                return num;
            }
        }
    }
#endif
}