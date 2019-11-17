using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using static Kerberos.NET.BinaryExtensions;

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
    }
}
