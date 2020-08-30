// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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
            var bytes = TryGetArrayFast(this.data);

            return stream.WriteAsync(bytes, 0, bytes.Length);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = this.data.Length;

            return true;
        }
    }
}
