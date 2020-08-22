// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class NegotiateMessage
    {
        public NegotiateMessageHeader Header { get; }

        public ReadOnlyMemory<byte> Random { get; }

        public ulong ProtocolVersion { get; }

        public AuthScheme AuthSchemes { get; }

        public ExtensionVector Extensions { get; }

        public NegotiateMessage(ReadOnlyMemory<byte> data)
        {
            this.Header = new NegotiateMessageHeader(data, out BinaryReader reader);

            this.Random = reader.ReadBytes(32);
            this.ProtocolVersion = reader.ReadUInt64();

            this.AuthSchemes = new AuthScheme(reader);
            this.Extensions = new ExtensionVector(reader);

            reader.Dispose();
        }
    }
}