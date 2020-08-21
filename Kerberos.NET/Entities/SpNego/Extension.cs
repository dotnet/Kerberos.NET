// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class Extension
    {
        public uint Type { get; }

        public ReadOnlyMemory<byte> Value { get; }

        public Extension(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            this.Type = reader.ReadUInt32();

            var offset = reader.ReadUInt32();
            var length = reader.ReadUInt32();

            var current = reader.BaseStream.Position;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            reader.BaseStream.Seek(offset, SeekOrigin.Begin);

            this.Value = reader.ReadBytes((int)length);

            reader.BaseStream.Seek(current, SeekOrigin.Begin);
        }
    }
}