using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal class BinaryContent : HttpContent
    {
        private readonly ReadOnlyMemory<byte> data;

        public BinaryContent(ReadOnlyMemory<byte> data)
        {
            this.data = data;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            var bytes = TryGetArrayFast(data);

            return stream.WriteAsync(bytes, 0, bytes.Length);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = data.Length;

            return true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static byte[] TryGetArrayFast(ReadOnlyMemory<byte> bytes)
        {
            if (MemoryMarshal.TryGetArray(bytes, out ArraySegment<byte> segment) && segment.Array.Length == bytes.Length)
            {
                return segment.Array;
            }
            else
            {
                return bytes.ToArray();
            }
        }
    }
}
