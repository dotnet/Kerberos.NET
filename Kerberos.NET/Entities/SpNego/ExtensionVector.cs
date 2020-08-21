// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;

namespace Kerberos.NET.Entities
{
    public class ExtensionVector
    {
        [KerberosIgnore]
        public uint ExtensionArrayOffset { get; }

        [KerberosIgnore]
        public ushort ExtensionCount { get; }

        public IEnumerable<Extension> Extensions { get; }

        public ExtensionVector(BinaryReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            this.ExtensionArrayOffset = reader.ReadUInt32();
            this.ExtensionCount = reader.ReadUInt16();

            var extensions = new Extension[this.ExtensionCount];

            var offset = reader.BaseStream.Position;

            reader.BaseStream.Seek(0, SeekOrigin.Begin);
            reader.BaseStream.Seek(this.ExtensionArrayOffset, SeekOrigin.Begin);

            for (var i = 0; i < this.ExtensionCount; i++)
            {
                extensions[i] = new Extension(reader);
            }

            this.Extensions = extensions;

            reader.BaseStream.Seek(offset, SeekOrigin.Begin);
        }
    }
}