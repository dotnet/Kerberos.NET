using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Kerberos.NET.Transport
{
    internal class BinaryContent : HttpContent
    {
        private readonly ReadOnlyMemory<byte> _data;

        public BinaryContent(ReadOnlyMemory<byte> data)
        {
            _data = data;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            ArraySegment<byte> bytes = _data.GetArraySegment();

            return stream.WriteAsync(bytes.Array, bytes.Offset, bytes.Count);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _data.Length;

            return true;
        }
    }
}
